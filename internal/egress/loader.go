package egress

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	execPayloadSize = 16 + 256 + 512
	pipePayloadSize = 8 + 4 + 4 + 128
	dnsPayloadSize  = 256
	sniPayloadSize  = 256
)

// Loader 负责加载 eBPF 程序集、挂载各类 hook 并读取事件。
type Loader struct {
	coll   *ebpf.Collection
	links  []link.Link
	rd     *ringbuf.Reader
	taints *ebpf.Map
}

// Load 从 eBPF 对象字节加载程序集，挂载 execve tracepoint 与 pipe 读写 hook。
func Load(obj []byte) (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("移除内存锁限制: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
	if err != nil {
		return nil, fmt.Errorf("解析 eBPF 对象: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("加载 eBPF 集合: %w", err)
	}

	ldr := &Loader{coll: coll}

	type attachSpec struct {
		prog         *ebpf.Program
		isTracepoint bool
		group        string
		name         string
	}
	attaches := []attachSpec{
		{coll.Programs["trace_execve"], true, "syscalls", "sys_enter_execve"},
		{coll.Programs["vfs_write_entry"], false, "", ""},
		{coll.Programs["vfs_read_exit"], false, "", ""},
		{coll.Programs["udp_sendmsg_entry"], false, "", ""},
		{coll.Programs["tcp_sendmsg_entry"], false, "", ""},
		{coll.Programs["task_alloc_entry"], false, "", ""},
		{coll.Programs["trace_exit"], true, "sched", "sched_process_exit"},
	}
	for _, a := range attaches {
		if a.prog == nil {
			ldr.Close()
			return nil, fmt.Errorf("未找到程序 %s", progName(a))
		}
		var l link.Link
		if a.isTracepoint {
			l, err = link.Tracepoint(a.group, a.name, a.prog, nil)
		} else {
			l, err = link.AttachTracing(link.TracingOptions{Program: a.prog})
		}
		if err != nil {
			ldr.Close()
			return nil, fmt.Errorf("挂载程序: %w", err)
		}
		ldr.links = append(ldr.links, l)
	}

	rm := coll.Maps["events"]
	if rm == nil {
		ldr.Close()
		return nil, errors.New("未找到 map events")
	}
	ldr.rd, err = ringbuf.NewReader(rm)
	if err != nil {
		ldr.Close()
		return nil, fmt.Errorf("创建 ring buffer 读取器: %w", err)
	}

	ldr.taints = coll.Maps["taints"]
	if ldr.taints == nil {
		ldr.Close()
		return nil, errors.New("未找到 map taints")
	}

	return ldr, nil
}

// Read 阻塞读取下一条事件。
func (l *Loader) Read() (*Event, error) {
	record, err := l.rd.Read()
	if err != nil {
		return nil, fmt.Errorf("读取 ring buffer: %w", err)
	}
	return parseEvent(record.RawSample)
}

// MarkTaint 写入 pid 的污点标记（agent 端显式注入根进程标记）。
func (l *Loader) MarkTaint(pid uint32, taint AdrTaint) error {
	if l.taints == nil {
		return errors.New("taints map 未加载")
	}
	return l.taints.Update(pid, taint, ebpf.UpdateAny)
}

// GetTaint 读取 pid 的污点标记。
func (l *Loader) GetTaint(pid uint32) (*AdrTaint, error) {
	if l.taints == nil {
		return nil, errors.New("taints map 未加载")
	}
	var t AdrTaint
	if err := l.taints.Lookup(pid, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// Close 释放加载器占用的全部资源。
func (l *Loader) Close() error {
	var errs []error
	if l.rd != nil {
		if err := l.rd.Close(); err != nil {
			errs = append(errs, fmt.Errorf("关闭 ring buffer 读取器: %w", err))
		}
	}
	for _, ln := range l.links {
		if err := ln.Close(); err != nil {
			errs = append(errs, fmt.Errorf("关闭 link: %w", err))
		}
	}
	if l.coll != nil {
		l.coll.Close()
	}
	return errors.Join(errs...)
}

// parseEvent 将 ring buffer 原始字节解析为 Event。
func parseEvent(raw []byte) (*Event, error) {
	if len(raw) < AdrEventHeaderSize {
		return nil, fmt.Errorf("事件过短: %d 字节", len(raw))
	}

	var e Event
	if err := binary.Read(bytes.NewReader(raw[:AdrEventHeaderSize]), binary.LittleEndian, &e.Header); err != nil {
		return nil, fmt.Errorf("解析事件头: %w", err)
	}

	payload := raw[AdrEventHeaderSize:]
	switch e.Header.Type {
	case EventTypeExec:
		if len(payload) < execPayloadSize {
			return nil, fmt.Errorf("EXEC payload 过短: %d 字节", len(payload))
		}
		p := new(ExecPayload)
		if err := binary.Read(bytes.NewReader(payload), binary.LittleEndian, p); err != nil {
			return nil, fmt.Errorf("解析 EXEC payload: %w", err)
		}
		e.Exec = p
	case EventTypePipe:
		if len(payload) < pipePayloadSize {
			return nil, fmt.Errorf("PIPE payload 过短: %d 字节", len(payload))
		}
		p := new(PipePayload)
		if err := binary.Read(bytes.NewReader(payload), binary.LittleEndian, p); err != nil {
			return nil, fmt.Errorf("解析 PIPE payload: %w", err)
		}
		e.Pipe = p
	case EventTypeDNS:
		if len(payload) < dnsPayloadSize {
			return nil, fmt.Errorf("DNS payload 过短: %d 字节", len(payload))
		}
		p := new(DnsPayload)
		if err := binary.Read(bytes.NewReader(payload), binary.LittleEndian, p); err != nil {
			return nil, fmt.Errorf("解析 DNS payload: %w", err)
		}
		e.Dns = p
	case EventTypeSNI:
		if len(payload) < sniPayloadSize {
			return nil, fmt.Errorf("SNI payload 过短: %d 字节", len(payload))
		}
		p := new(SniPayload)
		if err := binary.Read(bytes.NewReader(payload), binary.LittleEndian, p); err != nil {
			return nil, fmt.Errorf("解析 SNI payload: %w", err)
		}
		e.Sni = p
	default:
		// 未知事件类型，忽略 payload
	}
	return &e, nil
}

// progName 返回 attach 目标的程序名（供错误信息使用）。
func progName(a struct {
	prog         *ebpf.Program
	isTracepoint bool
	group        string
	name         string
}) string {
	if a.name != "" {
		return a.name
	}
	if a.prog != nil {
		return a.prog.String()
	}
	return ""
}
