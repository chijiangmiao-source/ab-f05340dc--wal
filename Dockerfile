# 星载姿控参数崩溃恢复审计服务
# 仅依赖 Python 标准库,构建无需联网安装任何包
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000

WORKDIR /srv

COPY app/ ./app/
COPY verify/ ./verify/

# 构建期语法检查,并以非 root 运行
RUN python -m compileall -q app verify \
    && useradd --system --uid 10001 --home /srv auditor \
    && chown -R auditor:auditor /srv

USER auditor
EXPOSE 8000

# 服务进程:app 容器默认命令;verify 容器在 compose 中覆盖为测试入口
CMD ["python", "app/server.py"]
