package rule

import (
	"fmt"
	"os"

	"github.com/fsnotify/fsnotify"
)

// Watcher 监听规则文件变化并热更新引擎。
type Watcher struct {
	path   string
	engine *Engine
	fsw    *fsnotify.Watcher
}

// NewWatcher 加载规则文件并创建监听器。
func NewWatcher(path string) (*Watcher, error) {
	rules, err := LoadFile(path)
	if err != nil {
		return nil, err
	}

	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("创建 fsnotify 监听: %w", err)
	}
	if err := fsw.Add(path); err != nil {
		if cerr := fsw.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "关闭 fsnotify 失败: %v\n", cerr)
		}
		return nil, fmt.Errorf("监听规则文件 %s: %w", path, err)
	}

	return &Watcher{
		path:   path,
		engine: NewEngine(rules),
		fsw:    fsw,
	}, nil
}

// Engine 返回规则引擎。
func (w *Watcher) Engine() *Engine {
	return w.engine
}

// Run 阻塞监听规则文件变化，变化时重新加载并替换引擎规则。
func (w *Watcher) Run() {
	for {
		select {
		case event, ok := <-w.fsw.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}
			rules, err := LoadFile(w.path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "重新加载规则失败: %v\n", err)
				continue
			}
			w.engine.Replace(rules)
			fmt.Printf("规则已热更新: %d 条\n", len(rules))
		case err, ok := <-w.fsw.Errors:
			if !ok {
				return
			}
			fmt.Fprintln(os.Stderr, "fsnotify 错误:", err)
		}
	}
}

// Close 关闭监听器。
func (w *Watcher) Close() error {
	if err := w.fsw.Close(); err != nil {
		return fmt.Errorf("关闭 fsnotify: %w", err)
	}
	return nil
}
