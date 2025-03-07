export REQUEST_METHOD="GET"
export HTTP_AUTHORIZATION="Basic dXNlcjpwYXNz"  # user:pass
export PATH_INFO="/api/endpoint"       # 根据实际接口路径填写
export QUERY_STRING="param1=value1"    # 根据实际参数填写
export REMOTE_ADDR="127.0.0.1"         # 模拟客户端IP
export SERVER_NAME="localhost"         # 服务器名
export SERVER_PORT="80"                # 服务器端口
export GATEWAY_INTERFACE="CGI/1.1"     # CGI 版本
export SERVER_PROTOCOL="HTTP/1.1"      # HTTP 版本
export CONTENT_TYPE=""                 # GET 请求通常不需要
export CONTENT_LENGTH=""               # GET 请求通常没有请求体

env | grep HTTP_
env | grep PATH_INFO
env | grep QUERY_STRING

# 执行 CGI 程序
./qasan-qemu -E LD_PRELOAD=/home/wuhuang/fuzz/qasan/bypass_fcgi_accept.so -L /home/wuhuang/fuzz/qasan/cramfs-root ./spx_restservice
