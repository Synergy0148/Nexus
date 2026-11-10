# NEXUS 局域网聊天室



基于 FastAPI + WebSocket 构建的局域网超酷炫私人聊天室。



## 特性

- 炫酷科幻风 UI，全屏粒子与开屏动画

- 账号系统，支持头像与个人签名

- 实时 WebSocket 通信，支持消息流、@提及、私信

- 支持图片、任意文件、自定义表情包发送



## 快速启动

1. 安装依赖：`pip install -r requirements.txt`

2. 启动服务：`uvicorn mainapp --host 0.0.0.0 --port 8000`

3. 在浏览器访问：`http://127.0.0.18000`



## 目录结构

```text
.
├── main.py
├── requirements.txt
├── README.md
└── static
  └── index.html
