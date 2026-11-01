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

// Loader 负责加载 eBPF 程序、挂载 tracepoint 并读取 execve 事件。
type Loader struct {
	coll *ebpf.Collection
	link link.Link
	rd   *ringbuf.Reader
}

// Load 从 eBPF 对象字节加载程序、挂载 sys_enter_execve tracepoint 并创建事件读取器。
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

	prog := coll.Programs["trace_execve"]
	if prog == nil {
		coll.Close()
		return nil, errors.New("未找到程序 trace_execve")
	}

	l, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("挂载 tracepoint: %w", err)
	}

	rm := coll.Maps["events"]
	if rm == nil {
		l.Close()
		coll.Close()
		return nil, errors.New("未找到 map events")
	}

	rd, err := ringbuf.NewReader(rm)
	if err != nil {
		l.Close()
		coll.Close()
		return nil, fmt.Errorf("创建 ring buffer 读取器: %w", err)
	}

	return &Loader{coll: coll, link: l, rd: rd}, nil
}

// Read 阻塞读取下一条 execve 事件。
func (l *Loader) Read() (*ExecveEvent, error) {
	record, err := l.rd.Read()
	if err != nil {
		return nil, fmt.Errorf("读取 ring buffer: %w", err)
	}
	return parseEvent(record.RawSample)
}

// Close 释放加载器占用的全部资源。
func (l *Loader) Close() error {
	var errs []error
	if l.rd != nil {
		if err := l.rd.Close(); err != nil {
			errs = append(errs, fmt.Errorf("关闭 ring buffer 读取器: %w", err))
		}
	}
	if l.link != nil {
		if err := l.link.Close(); err != nil {
			errs = append(errs, fmt.Errorf("关闭 tracepoint link: %w", err))
		}
	}
	if l.coll != nil {
		l.coll.Close()
	}
	return errors.Join(errs...)
}

// parseEvent 将 ring buffer 原始字节解析为 ExecveEvent。
func parseEvent(raw []byte) (*ExecveEvent, error) {
	if len(raw) < ExecveEventSize {
		return nil, fmt.Errorf("事件过短: %d 字节", len(raw))
	}

	var e ExecveEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
		return nil, fmt.Errorf("解析事件: %w", err)
	}
	return &e, nil
}
