FROM ubuntu:20.04

# 更新软件包索引并安装必要的依赖项
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    wget \
    tar \
    git \
    ca-certificates

# 下载、编译并安装 OpenSSL 3.0.0
RUN wget https://www.openssl.org/source/openssl-3.0.0.tar.gz \
    && tar xzf openssl-3.0.0.tar.gz \
    && cd openssl-3.0.0 \
    && ./config --prefix=/usr/local/openssl \
    && make -j$(nproc) \
    && make install \
    && cd .. \
    && rm -rf openssl-3.0.0 openssl-3.0.0.tar.gz

# 设置 OpenSSL 环境变量
ENV LD_LIBRARY_PATH=/usr/local/openssl/lib
ENV PATH="/usr/local/openssl/bin:${PATH}"
ENV CPATH=/usr/local/openssl/include

# 验证 OpenSSL 版本
#RUN openssl version

# 设置工作目录
WORKDIR /app

# 暴露需要的端口
EXPOSE 80 443

# 设置容器启动命令
CMD ["bash"]
