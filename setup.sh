#!/usr/bin/env bash
# ADR 开发环境一键初始化（Ubuntu 24.04，不含 Docker）
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "请以 root 运行，或使用: sudo ./setup.sh"
  exit 1
fi

echo "==> 更新软件源"
apt-get update

echo "==> 安装编译链 / eBPF / Git / 数据库"
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  build-essential gcc g++ make cmake pkg-config \
  clang llvm lld \
  libbpf-dev libelf-dev zlib1g-dev libssl-dev libcap-dev \
  git gh \
  python3-pip python3-venv \
  postgresql postgresql-contrib postgresql-16-pgvector redis-server

echo "==> 启动并启用数据库服务"
systemctl enable --now postgresql redis-server
sudo -u postgres psql -c "CREATE EXTENSION IF NOT EXISTS vector;" || true

echo "==> 检查 Go / Node（未安装请自行安装）"
go version || echo "提示：请安装 Go >= 1.22"
node --version || echo "提示：请安装 Node >= 20"

echo "==> 完成。还需手动执行："
echo "    git config --global user.name  \"你的名字\""
echo "    git config --global user.email \"你的邮箱\""
echo "    gh auth login"
