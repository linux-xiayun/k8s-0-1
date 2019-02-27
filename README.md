### 环境说明
系统：Centos 7.5.1804  
内核：3.10.0-862.el7.x86_64  
master1 为Master，master2既为Master也是Node，node1为Node
```
192.168.88.143 master1
192.168.88.131 master2
192.168.88.166 node1
```
### 初始化环境

```
#编辑 /etc/hosts 文件，配置hostname 通信
vi /etc/hosts

192.168.88.143 master1
192.168.88.131 master2
192.168.88.166 node1
```

```
#关闭防火墙
systemctl stop firewalld.service
systemctl disable firewalld.service
```
```
#主机免密
ssh-keygen 
ssh-copy-id -i ~/.ssh/id_rsa.pub master2 
ssh-copy-id -i ~/.ssh/id_rsa.pub node1
```

### 创建验证
这里使用 CloudFlare 的 PKI 工具集 cfssl 来生成 Certificate Authority (CA) 证书和秘钥文件。
#### 安装 cfssl

```
mkdir -p /opt/local/cfssl

cd /opt/local/cfssl

wget https://pkg.cfssl.org/R1.2/cfssl_linux-amd64
mv cfssl_linux-amd64 cfssl

wget https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64
mv cfssljson_linux-amd64 cfssljson

wget https://pkg.cfssl.org/R1.2/cfssl-certinfo_linux-amd64
mv cfssl-certinfo_linux-amd64 cfssl-certinfo

chmod +x *
```

```
#增加命令环境路径
echo "export PATH=$PATH:/opt/local/cfssl" >>  /etc/profile
```

#### 创建 CA 证书配置

```
mkdir /opt/ssl

cd /opt/ssl
```
```
# config.json 文件

vi  config.json

{
  "signing": {
    "default": {
      "expiry": "87600h"
    },
    "profiles": {
      "kubernetes": {
        "usages": [
            "signing",
            "key encipherment",
            "server auth",
            "client auth"
        ],
        "expiry": "87600h"
      }
    }
  }
}
```
```
# csr.json 文件

vi csr.json

{
  "CN": "kubernetes",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "HangZhou",
      "L": "HangZhou",
      "O": "k8s",
      "OU": "System"
    }
  ]
}
```
#### 生成 CA 证书和私钥
```
cd /opt/ssl

cfssl gencert -initca csr.json | cfssljson -bare ca
```
#### 分发证书
```
# 创建证书目录
mkdir -p /etc/kubernetes/ssl

# 拷贝所有文件到目录下
cp *.pem /etc/kubernetes/ssl
cp ca.csr /etc/kubernetes/ssl

# 这里要将文件拷贝到所有的k8s 机器上
scp *.pem *.csr master2:/etc/kubernetes/ssl/
scp *.pem *.csr node1:/etc/kubernetes/ssl/
```
### 安装 docker
官方最新版本 docker 为 18.06.1 , 官方验证最高版本支持到 18.06.0

```
# 导入 yum 源

# 安装 yum-config-manager
yum -y install yum-utils

# 导入
yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

# 更新 repo
yum makecache

# 查看yum 版本
yum list docker-ce.x86_64  --showduplicates |sort -r

# 安装指定版本 docker-ce 18.06 被 docker-ce-selinux 依赖
# 不能直接yum 安装 docker-ce-selinux
wget https://download.docker.com/linux/centos/7/x86_64/stable/Packages/docker-ce-18.06.0.ce-3.el7.x86_64.rpm

rpm -ivh docker-ce-18.06.0.ce-3.el7.x86_64.rpm

yum install -y libcgroup libseccomp* container-selinux

yum -y install docker-ce-18.06.0.ce

# 查看安装
docker version
```
#### 更改docker 配置

```
# 添加配置

vi /etc/systemd/system/docker.service

[Unit]
Description=Docker Application Container Engine
Documentation=http://docs.docker.com
After=network.target docker-storage-setup.service
Wants=docker-storage-setup.service

[Service]
Type=notify
Environment=GOTRACEBACK=crash
ExecReload=/bin/kill -s HUP $MAINPID
Delegate=yes
KillMode=process
ExecStart=/usr/bin/dockerd \
          $DOCKER_OPTS \
          $DOCKER_STORAGE_OPTIONS \
          $DOCKER_NETWORK_OPTIONS \
          $DOCKER_DNS_OPTIONS \
          $INSECURE_REGISTRY
LimitNOFILE=1048576
LimitNPROC=1048576
LimitCORE=infinity
TimeoutStartSec=1min
Restart=on-abnormal

[Install]
WantedBy=multi-user.target

```

```
# 修改其他配置

# 低版本内核， kernel 3.10.x  配置使用 overlay2

vi /etc/docker/daemon.json

{
  "storage-driver": "overlay2",
  "storage-opts": [
    "overlay2.override_kernel_check=true"
  ]
}
```
```
mkdir -p /etc/systemd/system/docker.service.d/

vi /etc/systemd/system/docker.service.d/docker-options.conf

[Service]
Environment="DOCKER_OPTS=--insecure-registry=10.254.0.0/16 --registry-mirror=http://b438f72b.m.daocloud.io --data-root=/opt/docker --log-opt max-size=50m --log-opt max-file=5"
~
```

```
vi /etc/systemd/system/docker.service.d/docker-dns.conf

[Service]
Environment="DOCKER_DNS_OPTIONS=--dns 10.254.0.2 --dns 114.114.114.114 --dns-search default.svc.cluster.local  --dns-search svc.cluster.local --dns-opt ndots:2 --dns-opt timeout:2 --dns-opt attempts:2"
```

```
# 重新读取配置，启动 docker 
systemctl daemon-reload
systemctl start docker
systemctl enable docker
```
### etcd 集群
etcd 是k8s集群最重要的组件， etcd 挂了，集群就挂了， 1.13.1 etcd 支持最新版本为 v3.2.24
#### 安装 etcd
官方地址 https://github.com/coreos/etcd/releases

```
wget https://github.com/coreos/etcd/releases/download/v3.2.24/etcd-v3.2.24-linux-amd64.tar.gz

tar zxvf etcd-v3.2.24-linux-amd64.tar.gz

cd etcd-v3.2.24-linux-amd64

mv etcd  etcdctl /usr/bin/
```
#### 创建 etcd 证书
etcd 证书这里，默认配置三个，后续如果需要增加，更多的 etcd 节点 这里的认证IP 请多预留几个，以备后续添加能通过认证，不需要重新签发

```
cd /opt/ssl/

vi etcd-csr.json

 "CN": "etcd",
  "hosts": [
    "127.0.0.1",
    "192.168.88.143",
    "192.168.88.131",
    "192.168.88.166"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "HangZhou",
      "L": "HangZhou",
      "O": "k8s",
      "OU": "System"
    }
  ]
}
```
```
# 生成 etcd 密钥
cfssl gencert -ca=/opt/ssl/ca.pem -ca-key=/opt/ssl/ca-key.pem -config=/opt/ssl/config.json -profile=kubernetes etcd-csr.json |cfssljson -bare etcd

#分发到etcd服务器
scp etcd*.pem master2:/etc/kubernetes/ssl/
scp etcd*.pem node1:/etc/kubernetes/ssl/

# 如果 etcd 非 root 用户，读取证书会提示没权限
chmod 644 /etc/kubernetes/ssl/etcd-key.pem
```
#### 修改 etcd 配置
由于 etcd 是最重要的组件，所以 –data-dir 请配置到其他路径中

```
# 创建 etcd data 目录， 并授权

useradd etcd

mkdir -p /opt/etcd

chown -R etcd:etcd /opt/etcd
```

```
#master1

vi /etc/systemd/system/etcd.service

[Unit]
Description=Etcd Server
After=network.target
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
WorkingDirectory=/opt/etcd/
User=etcd
# set GOMAXPROCS to number of processors
ExecStart=/usr/bin/etcd \
  --name=etcd1 \
  --cert-file=/etc/kubernetes/ssl/etcd.pem \
  --key-file=/etc/kubernetes/ssl/etcd-key.pem \
  --peer-cert-file=/etc/kubernetes/ssl/etcd.pem \
  --peer-key-file=/etc/kubernetes/ssl/etcd-key.pem \
  --trusted-ca-file=/etc/kubernetes/ssl/ca.pem \
  --peer-trusted-ca-file=/etc/kubernetes/ssl/ca.pem \
  --initial-advertise-peer-urls=https://192.168.88.143:2380 \
  --listen-peer-urls=https://192.168.88.143:2380 \
  --listen-client-urls=https://192.168.88.143:2379,http://127.0.0.1:2379 \
  --advertise-client-urls=https://192.168.88.143:2379 \
  --initial-cluster-token=k8s-etcd-cluster \
  --initial-cluster=etcd1=https://192.168.88.143:2380,etcd2=https://192.168.88.131:2380,etcd3=https://192.168.88.166:2380 \
  --initial-cluster-state=new \
  --data-dir=/opt/etcd/
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

```
#master2

vi /etc/systemd/system/etcd.service

[Unit]
Description=Etcd Server
After=network.target
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
WorkingDirectory=/opt/etcd/
User=etcd
# set GOMAXPROCS to number of processors
ExecStart=/usr/bin/etcd \
  --name=etcd2 \
  --cert-file=/etc/kubernetes/ssl/etcd.pem \
  --key-file=/etc/kubernetes/ssl/etcd-key.pem \
  --peer-cert-file=/etc/kubernetes/ssl/etcd.pem \
  --peer-key-file=/etc/kubernetes/ssl/etcd-key.pem \
  --trusted-ca-file=/etc/kubernetes/ssl/ca.pem \
  --peer-trusted-ca-file=/etc/kubernetes/ssl/ca.pem \
  --initial-advertise-peer-urls=https://192.168.88.131:2380 \
  --listen-peer-urls=https://192.168.88.131:2380 \
  --listen-client-urls=https://192.168.88.131:2379,http://127.0.0.1:2379 \
  --advertise-client-urls=https://192.168.88.131:2379 \
  --initial-cluster-token=k8s-etcd-cluster \
  --initial-cluster=etcd1=https://192.168.88.143:2380,etcd2=https://192.168.88.131:2380,etcd3=https://192.168.88.166:2380 \
  --initial-cluster-state=new \
  --data-dir=/opt/etcd/
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

```
#node1

vi /etc/systemd/system/etcd.service

[Unit]
Description=Etcd Server
After=network.target
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
WorkingDirectory=/opt/etcd/
User=etcd
# set GOMAXPROCS to number of processors
ExecStart=/usr/bin/etcd \
  --name=etcd3 \
  --cert-file=/etc/kubernetes/ssl/etcd.pem \
  --key-file=/etc/kubernetes/ssl/etcd-key.pem \
  --peer-cert-file=/etc/kubernetes/ssl/etcd.pem \
  --peer-key-file=/etc/kubernetes/ssl/etcd-key.pem \
  --trusted-ca-file=/etc/kubernetes/ssl/ca.pem \
  --peer-trusted-ca-file=/etc/kubernetes/ssl/ca.pem \
  --initial-advertise-peer-urls=https://192.168.88.166:2380 \
  --listen-peer-urls=https://192.168.88.166:2380 \
  --listen-client-urls=https://192.168.88.166:2379,http://127.0.0.1:2379 \
  --advertise-client-urls=https://192.168.88.166:2379 \
  --initial-cluster-token=k8s-etcd-cluster \
  --initial-cluster=etcd1=https://192.168.88.143:2380,etcd2=https://192.168.88.131:2380,etcd3=https://192.168.88.166:2380 \
  --initial-cluster-state=new \
  --data-dir=/opt/etcd/
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```
#### 启动 etcd
分别启动 所有节点的 etcd 服务

```
systemctl daemon-reload
systemctl enable etcd
systemctl start etcd
systemctl status etcd
```
#### 验证 etcd 集群状态

```
#查看etcd 集群状态
etcdctl --endpoints=https://192.168.88.143:2379,https://192.168.88.131:2379,https://192.168.88.166:2379 --cert-file=/etc/kubernetes/ssl/etcd.pem --ca-file=/etc/kubernetes/ssl/ca.pem --key-file=/etc/kubernetes/ssl/etcd-key.pem  cluster-health
```

```
#查看 etcd 集群成员
 etcdctl --endpoints=https://192.168.88.143:2379,https://192.168.88.131:2379,https://192.168.88.166:2379 --cert-file=/etc/kubernetes/ssl/etcd.pem --ca-file=/etc/kubernetes/ssl/ca.pem --key-file=/etc/kubernetes/ssl/etcd-key.pem  member list
```
### 配置 Kubernetes 集群
kubectl 安装在所有需要进行操作的机器上
#### Master and Node
*Master 需要部署 kube-apiserver , kube-scheduler , kube-controller-manager 这三个组件。 kube-scheduler 作用是调度pods分配到那个node里，简单来说就是资源调度。*

*kube-controller-manager 作用是 对 deployment controller , replication controller, endpoints controller, namespace controller, and serviceaccounts controller等等的循环控制，与kube-apiserver交互。*

#### 安装组件

```
wget https://dl.k8s.io/v1.13.1/kubernetes-server-linux-amd64.tar.gz

tar zxvf kubernetes-server-linux-amd64.tar.gz 

cd kubernetes

cp -r server/bin/{kube-apiserver,kube-controller-manager,kube-scheduler,kubectl,kubelet,kubeadm} /usr/local/bin/

scp server/bin/{kube-apiserver,kube-controller-manager,kube-scheduler,kubectl,kube-proxy,kubelet,kubeadm} master2:/usr/local/bin/

scp server/bin/{kube-proxy,kubelet} node1:/usr/local/bin/
```
### 创建 admin 证书
kubectl 与 kube-apiserver 的安全端口通信，需要为安全通信提供 TLS 证书和秘钥。

```
cd /opt/ssl/

vi admin-csr.json

{
  "CN": "admin",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "HangZhou",
      "L": "HangZhou",
      "O": "system:masters",
      "OU": "System"
    }
  ]
}
```

```
# 生成 admin 证书和私钥
cd /opt/ssl/

cfssl gencert -ca=/etc/kubernetes/ssl/ca.pem -ca-key=/etc/kubernetes/ssl/ca-key.pem -config=/opt/ssl/config.json -profile=kubernetes admin-csr.json | cfssljson -bare admin

cp admin*.pem /etc/kubernetes/ssl/

scp admin*.pem master2:/etc/kubernetes/ssl/
```
### 生成 kubernetes 配置文件
生成证书相关的配置文件存储与 /root/.kube 目录中

```
# 配置 kubernetes 集群
kubectl config set-cluster kubernetes --certificate-authority=/etc/kubernetes/ssl/ca.pem --embed-certs=true --server=https://127.0.0.1:6443

# 配置 客户端认证
kubectl config set-credentials admin --client-certificate=/etc/kubernetes/ssl/admin.pem --embed-certs=true --client-key=/etc/kubernetes/ssl/admin-key.pem

kubectl config set-context kubernetes --cluster=kubernetes --user=admin

kubectl config use-context kubernetes
```
### 创建 kubernetes 证书

```
cd /opt/ssl

vi kubernetes-csr.json

{
  "CN": "kubernetes",
  "hosts": [
    "127.0.0.1",
    "192.168.88.143",
    "192.168.88.131",
    "192.168.88.166",
    "10.254.0.1",
    "kubernetes",
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster",
    "kubernetes.default.svc.cluster.local"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "HangZhou",
      "L": "HangZhou",
      "O": "k8s",
      "OU": "System"
    }
  ]
}
```
> 这里 hosts 字段中 三个 IP 分别为 127.0.0.1 本机， 172.16.1.64 和 172.16.1.65 为 Master 的IP，多个Master需要写多个。  10.254.0.1 为 kubernetes SVC 的 IP， 一般是 部署网络的第一个IP , 如: 10.254.0.1 ， 在启动完成后，我们使用   kubectl get svc ， 就可以查看到

#### 生成 kubernetes 证书和私钥

```
cfssl gencert -ca=/etc/kubernetes/ssl/ca.pem -ca-key=/etc/kubernetes/ssl/ca-key.pem -config=/opt/ssl/config.json -profile=kubernetes kubernetes-csr.json |cfssljson -bare kubernetes

cp kubernetes*.pem /etc/kubernetes/ssl/

scp kubernetes*.pem master2:/etc/kubernetes/ssl/
```
### 配置 kube-apiserver
kubelet 首次启动时向 kube-apiserver 发送 TLS Bootstrapping 请求，kube-apiserver 验证 kubelet 请求中的 token 是否与它配置的 token 一致，如果一致则自动为 kubelet生成证书和秘钥。

```
cd /etc/kubernetes

# 生成 token
head -c 16 /dev/urandom | od -An -t x | tr -d ' '

# 创建 encryption-config.yaml 配置

cat > encryption-config.yaml <<EOF
kind: EncryptionConfiguration
apiVersion: apiserver.config.k8s.io/v1
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: 40179b02a8f6da07d90392ae966f7749
      - identity: {}
EOF

# 生成高级审核配置文件
cat >> audit-policy.yaml <<EOF
# Log all requests at the Metadata level.
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata
EOF

scp *.yaml master2:/etc/kubernetes/
```
### 创建 kube-apiserver.service 文件

```
# 自定义 系统 service 文件一般存于 /etc/systemd/system/ 下
# 配置为 各自的本地 IP

vi /etc/systemd/system/kube-apiserver.service

[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target

[Service]
User=root
ExecStart=/usr/local/bin/kube-apiserver \
  --admission-control=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,ResourceQuota,NodeRestriction \
  --anonymous-auth=false \
  --encryption-provider-config=/etc/kubernetes/encryption-config.yaml \
  --advertise-address=192.168.88.143 \
  --allow-privileged=true \
  --apiserver-count=3 \
  --audit-policy-file=/etc/kubernetes/audit-policy.yaml \
  --audit-log-maxage=30 \
  --audit-log-maxbackup=3 \
  --audit-log-maxsize=100 \
  --audit-log-path=/var/log/kubernetes/audit.log \
  --authorization-mode=Node,RBAC \
  --bind-address=0.0.0.0 \
  --secure-port=6443 \
  --client-ca-file=/etc/kubernetes/ssl/ca.pem \
  --kubelet-client-certificate=/etc/kubernetes/ssl/kubernetes.pem \
  --kubelet-client-key=/etc/kubernetes/ssl/kubernetes-key.pem \
  --enable-swagger-ui=true \
  --etcd-cafile=/etc/kubernetes/ssl/ca.pem \
  --etcd-certfile=/etc/kubernetes/ssl/etcd.pem \
  --etcd-keyfile=/etc/kubernetes/ssl/etcd-key.pem \
  --etcd-servers=https://192.168.88.143:2379,https://192.168.88.131:2379,https://192.168.88.166:2379 \
  --event-ttl=1h \
  --kubelet-https=true \
  --insecure-bind-address=127.0.0.1 \
  --insecure-port=8080 \
  --service-account-key-file=/etc/kubernetes/ssl/ca-key.pem \
  --service-cluster-ip-range=10.254.0.0/18 \
  --service-node-port-range=30000-32000 \
  --tls-cert-file=/etc/kubernetes/ssl/kubernetes.pem \
  --tls-private-key-file=/etc/kubernetes/ssl/kubernetes-key.pem \
  --enable-bootstrap-token-auth \
  --v=1
Restart=on-failure
RestartSec=5
Type=notify
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```
>--encryption-provider-config ，替代之前 token.csv 文件;  
这里面要注意的是 --service-node-port-range=30000-32000,
这个地方是 映射外部端口时 的端口范围，随机映射也在这个范围内映射，指定映射端口必须也在这个范围内。

```
#master2
scp /etc/systemd/system/kube-apiserver.service master2:/etc/systemd/system/kube-apiserver.service

#修改
vi /etc/systemd/system/kube-apiserver.service

[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target

[Service]
User=root
ExecStart=/usr/local/bin/kube-apiserver \
  --admission-control=NamespaceLifecycle,LimitRanger,ServiceAccount,DefaultStorageClass,ResourceQuota,NodeRestriction \
  --anonymous-auth=false \
  --encryption-provider-config=/etc/kubernetes/encryption-config.yaml \
  --advertise-address=192.168.88.131 \
  --allow-privileged=true \
  --apiserver-count=3 \
  --audit-policy-file=/etc/kubernetes/audit-policy.yaml \
  --audit-log-maxage=30 \
  --audit-log-maxbackup=3 \
  --audit-log-maxsize=100 \
  --audit-log-path=/var/log/kubernetes/audit.log \
  --authorization-mode=Node,RBAC \
  --bind-address=0.0.0.0 \
  --secure-port=6443 \
  --client-ca-file=/etc/kubernetes/ssl/ca.pem \
  --kubelet-client-certificate=/etc/kubernetes/ssl/kubernetes.pem \
  --kubelet-client-key=/etc/kubernetes/ssl/kubernetes-key.pem \
  --enable-swagger-ui=true \
  --etcd-cafile=/etc/kubernetes/ssl/ca.pem \
  --etcd-certfile=/etc/kubernetes/ssl/etcd.pem \
  --etcd-keyfile=/etc/kubernetes/ssl/etcd-key.pem \
  --etcd-servers=https://192.168.88.143:2379,https://192.168.88.131:2379,https://192.168.88.166:2379 \
  --event-ttl=1h \
  --kubelet-https=true \
  --insecure-bind-address=127.0.0.1 \
  --insecure-port=8080 \
  --service-account-key-file=/etc/kubernetes/ssl/ca-key.pem \
  --service-cluster-ip-range=10.254.0.0/18 \
  --service-node-port-range=30000-32000 \
  --tls-cert-file=/etc/kubernetes/ssl/kubernetes.pem \
  --tls-private-key-file=/etc/kubernetes/ssl/kubernetes-key.pem \
  --enable-bootstrap-token-auth \
  --v=1
Restart=on-failure
RestartSec=5
Type=notify
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

#### 启动 kube-apiserver

```
systemctl daemon-reload
systemctl enable kube-apiserver
systemctl start kube-apiserver
systemctl status kube-apiserver
```
### 配置 kube-controller-manager

```
# 创建 kube-controller-manager.service 文件

vi /etc/systemd/system/kube-controller-manager.service


[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
ExecStart=/usr/local/bin/kube-controller-manager \
  --address=0.0.0.0 \
  --master=http://127.0.0.1:8080 \
  --allocate-node-cidrs=true \
  --service-cluster-ip-range=10.254.0.0/18 \
  --cluster-cidr=10.254.64.0/18 \
  --cluster-signing-cert-file=/etc/kubernetes/ssl/ca.pem \
  --cluster-signing-key-file=/etc/kubernetes/ssl/ca-key.pem \
  --feature-gates=RotateKubeletServerCertificate=true \
  --controllers=*,tokencleaner,bootstrapsigner \
  --experimental-cluster-signing-duration=86700h0m0s \
  --cluster-name=kubernetes \
  --service-account-private-key-file=/etc/kubernetes/ssl/ca-key.pem \
  --root-ca-file=/etc/kubernetes/ssl/ca.pem \
  --leader-elect=true \
  --node-monitor-grace-period=40s \
  --node-monitor-period=5s \
  --pod-eviction-timeout=5m0s \
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```
scp /etc/systemd/system/kube-controller-manager.service master2:/etc/systemd/system/kube-controller-manager.service
```

#### 启动 kube-controller-manager

```
systemctl daemon-reload
systemctl enable kube-controller-manager
systemctl start kube-controller-manager
systemctl status kube-controller-manager
```
### 配置 kube-scheduler

```
# 创建 kube-scheduler.service 文件

vi /etc/systemd/system/kube-scheduler.service


[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
ExecStart=/usr/local/bin/kube-scheduler \
  --address=0.0.0.0 \
  --master=http://127.0.0.1:8080 \
  --leader-elect=true \
  --v=1
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```
#### 启动 kube-scheduler

```
systemctl daemon-reload
systemctl enable kube-scheduler
systemctl start kube-scheduler
systemctl status kube-scheduler
```
### 验证 kube-scheduler 的 ha
kube-scheduler 通过配置 leader-elect=true 自动选择 leader
```
# 使用如下命令 可以查看 holderIdentity 字段中的前缀 来判断 leader

kubectl get endpoints kube-scheduler --namespace=kube-system  -o yaml

apiVersion: v1
kind: Endpoints
metadata:
  annotations:
    control-plane.alpha.kubernetes.io/leader: '{"holderIdentity":"k8s-master-01_f1cf93f7-303d-11e9-8f41-000c29435777","leaseDurationSeconds":15,"acquireTime":"2019-02-14T09:50:22Z","renewTime":"2019-02-16T02:26:51Z","leaderTransitions":0}'
  creationTimestamp: "2019-02-14T09:50:22Z"
  name: kube-scheduler
  namespace: kube-system
  resourceVersion: "161424"
  selfLink: /api/v1/namespaces/kube-system/endpoints/kube-scheduler
  uid: f2694ce1-303d-11e9-a5bf-000c29435777
```
#### 验证 Master 节点

```
[root@k8s-master-01 ~]# kubectl get componentstatuses
NAME                 STATUS    MESSAGE              ERROR
controller-manager   Healthy   ok                   
scheduler            Healthy   ok                   
etcd-1               Healthy   {"health": "true"}   
etcd-2               Healthy   {"health": "true"}   
etcd-0               Healthy   {"health": "true"}  

[root@k8s-master-02 ~]# kubectl get componentstatuses
NAME                 STATUS    MESSAGE              ERROR
controller-manager   Healthy   ok                   
scheduler            Healthy   ok                   
etcd-2               Healthy   {"health": "true"}   
etcd-0               Healthy   {"health": "true"}   
etcd-1               Healthy   {"health": "true"}   
```
### 配置 kubelet 认证
kubelet 授权 kube-apiserver 的一些操作 exec run logs 等

```
# RBAC 只需创建一次就可以

kubectl create clusterrolebinding kube-apiserver:kubelet-apis --clusterrole=system:kubelet-api-admin --user kubernetes
```
### 创建 bootstrap kubeconfig 文件
注意: token 生效时间为 1day , 超过时间未创建自动失效，需要重新创建 token

```
# 创建 集群所有 kubelet 的 token
kubeadm token create --description kubelet-bootstrap-token --groups system:bootstrappers:master1 --kubeconfig ~/.kube/config 
kubeadm token create --description kubelet-bootstrap-token --groups system:bootstrappers:master2 --kubeconfig ~/.kube/config 
kubeadm token create --description kubelet-bootstrap-token --groups system:bootstrappers:node1 --kubeconfig ~/.kube/config

kubeadm token list --kubeconfig ~/.kube/config 
TOKEN                     TTL       EXPIRES                     USAGES                   DESCRIPTION               EXTRA GROUPS
grnzfj.0fu7vh5exk5esxye   23h       2019-02-17T14:36:16+08:00   authentication,signing   kubelet-bootstrap-token   system:bootstrappers:master1
gs5o9d.a7b5e43hi3080zji   23h       2019-02-17T14:36:46+08:00   authentication,signing   kubelet-bootstrap-token   system:bootstrappers:master2
mbhyew.whfugdep0ohug9zr   23h       2019-02-17T14:37:21+08:00   authentication,signing   kubelet-bootstrap-token   system:bootstrappers:node1
```

```
#生成master1的bootstrap.kubeconfig

# 配置集群参数
kubectl config set-cluster kubernetes --certificate-authority=/etc/kubernetes/ssl/ca.pem --embed-certs=true --server=https://127.0.0.1:6443 --kubeconfig=master1-bootstrap.kubeconfig

# 配置客户端认证
kubectl config set-credentials kubelet-bootstrap --token=grnzfj.0fu7vh5exk5esxye --kubeconfig=master1-bootstrap.kubeconfig

# 配置关联
kubectl config set-context default --cluster=kubernetes --user=kubelet-bootstrap --kubeconfig=master1-bootstrap.kubeconfig

# 配置默认关联
kubectl config use-context default --kubeconfig=master1-bootstrap.kubeconfig

# 拷贝生成的 master1-bootstrap.kubeconfig 文件
mv master1-bootstrap.kubeconfig /etc/kubernetes/bootstrap.kubeconfig
```

```
#生成master2的bootstrap.kubeconfig

# 配置集群参数
kubectl config set-cluster kubernetes --certificate-authority=/etc/kubernetes/ssl/ca.pem --embed-certs=true --server=https://127.0.0.1:6443 --kubeconfig=master2-bootstrap.kubeconfig

# 配置客户端认证
kubectl config set-credentials kubelet-bootstrap --token=gs5o9d.a7b5e43hi3080zji --kubeconfig=master2-bootstrap.kubeconfig

# 配置关联
kubectl config set-context default --cluster=kubernetes --user=kubelet-bootstrap --kubeconfig=master2-bootstrap.kubeconfig

# 配置默认关联
kubectl config use-context default --kubeconfig=master2-bootstrap.kubeconfig

# 拷贝生成的 master2-bootstrap.kubeconfig 文件
scp master2-bootstrap.kubeconfig master2:/etc/kubernetes/bootstrap.kubeconfig
```

```
#生成node1的bootstrap.kubeconfig

# 配置集群参数
kubectl config set-cluster kubernetes --certificate-authority=/etc/kubernetes/ssl/ca.pem --embed-certs=true --server=https://127.0.0.1:6443 --kubeconfig=node1-bootstrap.kubeconfig

# 配置客户端认证
kubectl config set-credentials kubelet-bootstrap --token=mbhyew.whfugdep0ohug9zr --kubeconfig=node1-bootstrap.kubeconfig

# 配置关联
kubectl config set-context default --cluster=kubernetes --user=kubelet-bootstrap --kubeconfig=node1-bootstrap.kubeconfig

# 配置默认关联
kubectl config use-context default --kubeconfig=node1-bootstrap.kubeconfig

# 拷贝生成的 node1-bootstrap.kubeconfig 文件
scp node1-bootstrap.kubeconfig node1:/etc/kubernetes/bootstrap.kubeconfig
```

```
# 配置 bootstrap RBAC 权限

kubectl create clusterrolebinding kubelet-bootstrap --clusterrole=system:node-bootstrapper --group=system:bootstrappers
```
### 创建自动批准相关 CSR 请求的 ClusterRole

```
vi /etc/kubernetes/tls-instructs-csr.yaml

kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: system:certificates.k8s.io:certificatesigningrequests:selfnodeserver
rules:
- apiGroups: ["certificates.k8s.io"]
  resources: ["certificatesigningrequests/selfnodeserver"]
  verbs: ["create"]
```

```
# 导入 yaml 文件

kubectl apply -f /etc/kubernetes/tls-instructs-csr.yaml

# 查看

kubectl describe ClusterRole/system:certificates.k8s.io:certificatesigningrequests:selfnodeserver

Name:         system:certificates.k8s.io:certificatesigningrequests:selfnodeserver
Labels:       <none>
Annotations:  kubectl.kubernetes.io/last-applied-configuration:
                {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"annotations":{},"name":"system:certificates.k8s.io:certific...
PolicyRule:
  Resources                                                      Non-Resource URLs  Resource Names  Verbs
  ---------                                                      -----------------  --------------  -----
  certificatesigningrequests.certificates.k8s.io/selfnodeserver  []                 []              [create]
```

```
#  将 ClusterRole 绑定到适当的用户组


# 自动批准 system:bootstrappers 组用户 TLS bootstrapping 首次申请证书的 CSR 请求

kubectl create clusterrolebinding node-client-auto-approve-csr --clusterrole=system:certificates.k8s.io:certificatesigningrequests:nodeclient --group=system:bootstrappers


# 自动批准 system:nodes 组用户更新 kubelet 自身与 apiserver 通讯证书的 CSR 请求

kubectl create clusterrolebinding node-client-auto-renew-crt --clusterrole=system:certificates.k8s.io:certificatesigningrequests:selfnodeclient --group=system:nodes


# 自动批准 system:nodes 组用户更新 kubelet 10250 api 端口证书的 CSR 请求

kubectl create clusterrolebinding node-server-auto-renew-crt --clusterrole=system:certificates.k8s.io:certificatesigningrequests:selfnodeserver --group=system:nodes
```
### 创建 kubelet.service 文件
> 关于 kubectl get node 中的 ROLES 的标签
> 
> 单 Master 打标签 kubectl label node master1 node-role.kubernetes.io/master=""
> 
> 这里需要将 单Master 更改为 NoSchedule
> 
> 更新标签命令为 kubectl taint nodes master1 node-role.kubernetes.io/master=:NoSchedule
> 
> 既 Master 又是 node 打标签 kubectl label node master2 node-role.kubernetes.io/master=""
> 
> 单 Node 打标签 kubectl label node node1 node-role.kubernetes.io/node=""
> 
> 关于删除 label 可使用 - 号相连 如: kubectl label nodes node1 node-role.kubernetes.io/node-
#### 动态 kubelet 配置
==在启动kubelet之前，需要先手动创建/var/lib/kubelet目录==
```
#master1

# 创建 kubelet 目录

mkdir -p /var/lib/kubelet


vi /etc/systemd/system/kubelet.service

[Unit]
Description=Kubernetes Kubelet
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=docker.service
Requires=docker.service

[Service]
WorkingDirectory=/var/lib/kubelet
ExecStart=/usr/local/bin/kubelet \
  --hostname-override=master1 \
  --pod-infra-container-image=jicki/pause-amd64:3.1 \
  --bootstrap-kubeconfig=/etc/kubernetes/bootstrap.kubeconfig \
  --kubeconfig=/etc/kubernetes/kubelet.kubeconfig \
  --config=/etc/kubernetes/kubelet.config.json \
  --cert-dir=/etc/kubernetes/ssl \
  --logtostderr=true \
  --v=2

[Install]
WantedBy=multi-user.target
```

```
#master1

# 创建 kubelet config 配置文件

vi /etc/kubernetes/kubelet.config.json

{
  "kind": "KubeletConfiguration",
  "apiVersion": "kubelet.config.k8s.io/v1beta1",
  "authentication": {
    "x509": {
      "clientCAFile": "/etc/kubernetes/ssl/ca.pem"
    },
    "webhook": {
      "enabled": true,
      "cacheTTL": "2m0s"
    },
    "anonymous": {
      "enabled": false
    }
  },
  "authorization": {
    "mode": "Webhook",
    "webhook": {
      "cacheAuthorizedTTL": "5m0s",
      "cacheUnauthorizedTTL": "30s"
    }
  },
  "address": "192.168.88.143",
  "port": 10250,
  "readOnlyPort": 0,
  "cgroupDriver": "cgroupfs",
  "hairpinMode": "promiscuous-bridge",
  "serializeImagePulls": false,
  "RotateCertificates": true,
  "featureGates": {
    "RotateKubeletClientCertificate": true,
    "RotateKubeletServerCertificate": true
  },
  "MaxPods": "512",
  "failSwapOn": false,
  "containerLogMaxSize": "10Mi",
  "containerLogMaxFiles": 5,
  "clusterDomain": "cluster.local.",
  "clusterDNS": ["10.254.0.2"]
}
```

#### 启动 kubelet

```
systemctl daemon-reload
systemctl enable kubelet
systemctl start kubelet
systemctl status kubelet
```
### 配置 kube-proxy
#### 创建 kube-proxy 证书

```
# 证书方面由于我们node端没有装 cfssl
# 我们回到 master 端 机器 去配置证书，然后拷贝过来

cd /opt/ssl


vi kube-proxy-csr.json

{
  "CN": "system:kube-proxy",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "HangZhou",
      "L": "HangZhou",
      "O": "k8s",
      "OU": "System"
    }
  ]
}
```
### 生成 kube-proxy 证书和私钥

```
/opt/local/cfssl/cfssl gencert -ca=/etc/kubernetes/ssl/ca.pem -ca-key=/etc/kubernetes/ssl/ca-key.pem -config=/opt/ssl/config.json -profile=kubernetes  kube-proxy-csr.json | /opt/local/cfssl/cfssljson -bare kube-proxy

# 查看生成
ls kube-proxy*
kube-proxy.csr  kube-proxy-csr.json  kube-proxy-key.pem  kube-proxy.pem

# 拷贝到目录

cp kube-proxy* /etc/kubernetes/ssl/

scp kube-proxy* master2:/etc/kubernetes/ssl/

scp kube-proxy* node1:/etc/kubernetes/ssl/
```
#### 创建 kube-proxy kubeconfig 文件

```
# 配置集群

kubectl config set-cluster kubernetes --certificate-authority=/etc/kubernetes/ssl/ca.pem --embed-certs=true --server=https://127.0.0.1:6443 --kubeconfig=kube-proxy.kubeconfig


# 配置客户端认证

kubectl config set-credentials kube-proxy --client-certificate=/etc/kubernetes/ssl/kube-proxy.pem --client-key=/etc/kubernetes/ssl/kube-proxy-key.pem --embed-certs=true --kubeconfig=kube-proxy.kubeconfig
  
  
# 配置关联

 kubectl config set-context default --cluster=kubernetes --user=kube-proxy --kubeconfig=kube-proxy.kubeconfig



# 配置默认关联
kubectl config use-context default --kubeconfig=kube-proxy.kubeconfig

# 拷贝到需要的 node 端里

scp kube-proxy.kubeconfig master2:/etc/kubernetes/

scp kube-proxy.kubeconfig node1:/etc/kubernetes/
```
### 创建 kube-proxy.service 文件
> 1.10 官方 ipvs 已经是默认的配置 –masquerade-all 必须添加这项配置，否则 创建 svc 在 ipvs 不会添加规则
> 
> 打开 ipvs 需要安装 ipvsadm ipset conntrack 软件， 在 ==node== 中安装 yum install ipset ipvsadm conntrack-tools.x86_64 -y
> 
> yaml 配置文件中的 参数如下:
> 
> https://github.com/kubernetes/kubernetes/blob/master/pkg/proxy/apis/config/types.go

```
#master2
cd /etc/kubernetes/

vi  kube-proxy.config.yaml

apiVersion: kubeproxy.config.k8s.io/v1alpha1
bindAddress: 192.168.88.131 
clientConnection:
  kubeconfig: /etc/kubernetes/kube-proxy.kubeconfig
clusterCIDR: 10.254.64.0/18
healthzBindAddress: 192.168.88.131:10256
hostnameOverride: master2
kind: KubeProxyConfiguration
metricsBindAddress: 192.168.88.131:10249
mode: "ipvs"
```
==在启动kubelet之前，需要先手动创建/var/lib/kube-proxy目录==
```
# 创建 kube-proxy 目录

mkdir -p /var/lib/kube-proxy

vi /etc/systemd/system/kube-proxy.service

[Unit]
Description=Kubernetes Kube-Proxy Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target

[Service]
WorkingDirectory=/var/lib/kube-proxy
ExecStart=/usr/local/bin/kube-proxy \
  --config=/etc/kubernetes/kube-proxy.config.yaml \
  --logtostderr=true \
  --v=1
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```
#### 启动 kube-proxy

```
systemctl daemon-reload
systemctl enable kube-proxy
systemctl start kube-proxy
systemctl status kube-proxy
```

```
# 检查  ipvs
[root@k8s-master-02 kubernetes]# ipvsadm -L -n
IP Virtual Server version 1.2.1 (size=4096)
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port           Forward Weight ActiveConn InActConn
TCP  10.254.0.1:443 rr
  -> 192.168.88.131:6443          Masq    1      0          0         
  -> 192.168.88.143:6443          Masq    1      0          0 
```
#### ==至此 Master 端（master1） 与 Master and Node 端(master2)的安装完毕==
### Node 端
master 之间除 api server 以外其他组件通过 etcd 选举，api server 默认不作处理；
在每个 node 上启动一个 nginx，每个 nginx 反向代理所有 api server;
node 上 kubelet、kube-proxy 连接本地的 nginx 代理端口;
当 nginx 发现无法连接后端时会自动踢掉出问题的 api server，从而实现 api server 的 HA;
#### 发布证书

```
# ALL node

mkdir -p /etc/kubernetes/ssl/

scp ca.pem kube-proxy.pem kube-proxy-key.pem  node-*:/etc/kubernetes/ssl/
```
### 创建Nginx 代理
在每个 node 都必须创建一个 Nginx 代理， 这里特别注意， 当 Master 也做为 Node 的时候 不需要配置 Nginx-proxy，主要nginx代理端口为6443 kube-apiserver端口[*提供了HTTP Rest接口的关键服务进程，是kubernetes里所有资源的增删改查等操作的唯一入口，也是集群的入口进程，master节点所有*]
```
#node1
cat << EOF >> /etc/nginx/nginx.conf
error_log stderr notice;

worker_processes auto;
events {
  multi_accept on;
  use epoll;
  worker_connections 1024;
}

stream {
    upstream kube_apiserver {
        least_conn;
        server 192.168.88.131:6443;
        server 192.168.88.143:6443;
    }

    server {
        listen        0.0.0.0:6443;
        proxy_pass    kube_apiserver;
        proxy_timeout 10m;
        proxy_connect_timeout 1s;
    }
}
EOF

# 更新权限
chmod +r /etc/nginx/nginx.conf
```


```
# 配置 Nginx 基于 docker 进程，然后配置 systemd 来启动
cat << EOF >> /etc/systemd/system/nginx-proxy.service
[Unit]
Description=kubernetes apiserver docker wrapper
Wants=docker.socket
After=docker.service

[Service]
User=root
PermissionsStartOnly=true
ExecStart=/usr/bin/docker run -p 127.0.0.1:6443:6443 \\
                              -v /etc/nginx:/etc/nginx \\
                              --name nginx-proxy \\
                              --net=host \\
                              --restart=on-failure:5 \\
                              --memory=512M \\
                              nginx:1.13.7-alpine
ExecStartPre=-/usr/bin/docker rm -f nginx-proxy
ExecStop=/usr/bin/docker stop nginx-proxy
Restart=always
RestartSec=15s
TimeoutStartSec=30s

[Install]
WantedBy=multi-user.target
EOF
```

```
# 启动 Nginx

systemctl daemon-reload
systemctl start nginx-proxy
systemctl enable nginx-proxy
systemctl status nginx-proxy
```
### 配置 Kubelet.service 文件
#### systemd kubelet 配置
##### 动态 kubelet 配置
> 官方说明 https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ https://kubernetes.io/docs/tasks/administer-cluster/reconfigure-kubelet/
> 
> https://github.com/kubernetes/kubernetes/blob/release-1.12/pkg/kubelet/apis/config/types.go


```
#master2
# 创建 kubelet 目录

mkdir /var/lib/kubelet

vi /etc/systemd/system/kubelet.service


[Unit]
Description=Kubernetes Kubelet
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=docker.service
Requires=docker.service

[Service]
WorkingDirectory=/var/lib/kubelet
ExecStart=/usr/local/bin/kubelet \
  --hostname-override=master2 \
  --pod-infra-container-image=jicki/pause-amd64:3.1 \
  --bootstrap-kubeconfig=/etc/kubernetes/bootstrap.kubeconfig \
  --kubeconfig=/etc/kubernetes/kubelet.kubeconfig \
  --config=/etc/kubernetes/kubelet.config.json \
  --cert-dir=/etc/kubernetes/ssl \
  --logtostderr=true \
  --v=2

[Install]
WantedBy=multi-user.target
```

```
# 创建 kubelet config 配置文件

vi /etc/kubernetes/kubelet.config.json

{
  "kind": "KubeletConfiguration",
  "apiVersion": "kubelet.config.k8s.io/v1beta1",
  "authentication": {
    "x509": {
      "clientCAFile": "/etc/kubernetes/ssl/ca.pem"
    },
    "webhook": {
      "enabled": true,
      "cacheTTL": "2m0s"
    },
    "anonymous": {
      "enabled": false
    }
  },
  "authorization": {
    "mode": "Webhook",
    "webhook": {
      "cacheAuthorizedTTL": "5m0s",
      "cacheUnauthorizedTTL": "30s"
    }
  },
  "address": "192.168.88.131",
  "port": 10250,
  "readOnlyPort": 0,
  "cgroupDriver": "cgroupfs",
  "hairpinMode": "promiscuous-bridge",
  "serializeImagePulls": false,
  "featureGates": {
    "RotateKubeletClientCertificate": true,
    "RotateKubeletServerCertificate": true
  },
  "MaxPods": "512",
  "failSwapOn": false,
  "containerLogMaxSize": "10Mi",
  "containerLogMaxFiles": 5,
  "clusterDomain": "cluster.local.",
  "clusterDNS": ["10.254.0.2"]
}
```

```
#node1
# 创建 kubelet 目录

mkdir /var/lib/kubelet

vi /etc/systemd/system/kubelet.service


[Unit]
Description=Kubernetes Kubelet
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=docker.service
Requires=docker.service

[Service]
WorkingDirectory=/var/lib/kubelet
ExecStart=/usr/local/bin/kubelet \
  --hostname-override=node1 \
  --pod-infra-container-image=jicki/pause-amd64:3.1 \
  --bootstrap-kubeconfig=/etc/kubernetes/bootstrap.kubeconfig \
  --kubeconfig=/etc/kubernetes/kubelet.kubeconfig \
  --config=/etc/kubernetes/kubelet.config.json \
  --cert-dir=/etc/kubernetes/ssl \
  --logtostderr=true \
  --v=2

[Install]
WantedBy=multi-user.target
```

```
# 创建 kubelet config 配置文件

vi /etc/kubernetes/kubelet.config.json


{
  "kind": "KubeletConfiguration",
  "apiVersion": "kubelet.config.k8s.io/v1beta1",
  "authentication": {
    "x509": {
      "clientCAFile": "/etc/kubernetes/ssl/ca.pem"
    },
    "webhook": {
      "enabled": true,
      "cacheTTL": "2m0s"
    },
    "anonymous": {
      "enabled": false
    }
  },
  "authorization": {
    "mode": "Webhook",
    "webhook": {
      "cacheAuthorizedTTL": "5m0s",
      "cacheUnauthorizedTTL": "30s"
    }
  },
  "address": "192.168.88.166",
  "port": 10250,
  "readOnlyPort": 0,
  "cgroupDriver": "cgroupfs",
  "hairpinMode": "promiscuous-bridge",
  "serializeImagePulls": false,
  "featureGates": {
    "RotateKubeletClientCertificate": true,
    "RotateKubeletServerCertificate": true
  },
  "MaxPods": "512",
  "failSwapOn": false,
  "containerLogMaxSize": "10Mi",
  "containerLogMaxFiles": 5,
  "clusterDomain": "cluster.local.",
  "clusterDNS": ["10.254.0.2"]
}
```

```
# 启动 kubelet

systemctl daemon-reload
systemctl enable kubelet
systemctl start kubelet
systemctl status kubelet
```
#### 更改nodes roles labels

```
#单 Master 打标签 [master1]
kubectl label node master1 node-role.kubernetes.io/master=""

#这里需要将 单Master 更改为 NoSchedule
kubectl taint nodes master1 node-role.kubernetes.io/master=:NoSchedule

#既 Master 又是 node 打标签  [master2]
kubectl label node master2 node-role.kubernetes.io/master=""

#单 Node 打标签 [node1]
kubectl label node node1 node-role.kubernetes.io/node=""

#关于删除 label 可使用 - 号相连 如: 
kubectl label nodes node1 node-role.kubernetes.io/node-
```
### 配置 kube-proxy.service
```
#node1
cd /etc/kubernetes/

vi  kube-proxy.config.yaml


apiVersion: kubeproxy.config.k8s.io/v1alpha1
bindAddress: 192.168.88.166
clientConnection:
  kubeconfig: /etc/kubernetes/kube-proxy.kubeconfig
clusterCIDR: 10.254.64.0/18
healthzBindAddress: 192.168.88.166:10256
hostnameOverride: node1
kind: KubeProxyConfiguration
metricsBindAddress: 192.168.88.166:10249
mode: "ipvs"

```

```
# 创建 kube-proxy 目录


vi /etc/systemd/system/kube-proxy.service

[Unit]
Description=Kubernetes Kube-Proxy Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target

[Service]
WorkingDirectory=/var/lib/kube-proxy
ExecStart=/usr/local/bin/kube-proxy \
  --config=/etc/kubernetes/kube-proxy.config.yaml \
  --logtostderr=true \
  --v=1
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

```
#  启动

systemctl daemon-reload
systemctl enable kube-proxy
systemctl start kube-proxy
systemctl status kube-proxy
```
### 配置 Calico 网络
#### 下载 Calico yaml

```
# 下载 yaml 文件

wget https://docs.projectcalico.org/v3.4/getting-started/kubernetes/installation/hosted/calico.yaml
```
#### 下载镜像

```
# 下载 镜像

# 国外镜像 有墙
quay.io/calico/node:v3.3.1
quay.io/calico/cni:v3.3.1
quay.io/calico/kube-controllers:v3.3.1


# 国内镜像
jicki/node:v3.3.1
jicki/cni:v3.3.1
jicki/kube-controllers:v3.3.1



# 替换镜像
sed -i 's/quay\.io\/calico/jicki/g'  calico.yaml 
```
#### 修改配置

```
#master1
cd /etc/kubernetes
vi calico.yaml

# 注意修改如下选项:

修改所有镜像版本号为v3.3.1

# etcd 地址

  etcd_endpoints: "https://192.168.88.143:2379,https://192.168.88.131:2379,https://192.168.88.166:2379"
  
 
# etcd 证书路径
  # If you're using TLS enabled etcd uncomment the following.取消以下注释
  # You must also populate the Secret below with these files. 
    etcd_ca: "/calico-secrets/etcd-ca"  
    etcd_cert: "/calico-secrets/etcd-cert"
    etcd_key: "/calico-secrets/etcd-key"  

# etcd 证书 base64 地址 (执行里面的命令生成的证书 base64 码，填入里面)

data:
  etcd-key: (cat /etc/kubernetes/ssl/etcd-key.pem | base64 | tr -d '\n')
  etcd-cert: (cat /etc/kubernetes/ssl/etcd.pem | base64 | tr -d '\n')
  etcd-ca: (cat /etc/kubernetes/ssl/ca.pem | base64 | tr -d '\n')
  
# 修改 pods 分配的 IP 段

            - name: CALICO_IPV4POOL_CIDR
              value: "10.254.64.0/18"
```

```
#分发到其它节点
scp /etc/kubernetes/calico.yaml master2:/etc/kubernetes/
scp /etc/kubernetes/calico.yaml node1:/etc/kubernetes/
# 导入 yaml 文件
kubectl apply -f calico.yaml 
```
#### 修改 kubelet 配置

```
#   kubelet 需要增加 cni 插件    --network-plugin=cni

vi /etc/systemd/system/kubelet.service


  --network-plugin=cni \



# 重新加载配置

systemctl daemon-reload
systemctl restart kubelet.service
systemctl status kubelet.service
```
#### 安装 calicoctl
calicoctl 是 calico 网络的管理客户端, 只需要在一台 node 里配置既可。

```
# 下载 二进制文件

curl -O -L https://github.com/projectcalico/calicoctl/releases/download/v3.2.3/calicoctl

mv calicoctl /usr/local/bin/

chmod +x /usr/local/bin/calicoctl



# 创建 calicoctl.cfg 配置文件

mkdir /etc/calico

vi /etc/calico/calicoctl.cfg


apiVersion: projectcalico.org/v3
kind: CalicoAPIConfig
metadata:
spec:
  datastoreType: "kubernetes"
  kubeconfig: "/root/.kube/config"

# 查看 calico 状态
[root@k8s-master-01 kubernetes]# calicoctl node status
Calico process is running.

IPv4 BGP status
+----------------+-------------------+-------+------------+-------------+
|  PEER ADDRESS  |     PEER TYPE     | STATE |   SINCE    |    INFO     |
+----------------+-------------------+-------+------------+-------------+
| 192.168.88.131 | node-to-node mesh | up    | 2019-02-22 | Established |
| 192.168.88.166 | node-to-node mesh | up    | 2019-02-20 | Established |
+----------------+-------------------+-------+------------+-------------+

IPv6 BGP status
No IPv6 peers found.
```
### 配置 CoreDNS
官方 地址 https://coredns.io
#### 下载 yaml 文件

```
wget https://raw.githubusercontent.com/coredns/deployment/master/kubernetes/coredns.yaml.sed

mv coredns.yaml.sed coredns.yaml
```
1.2.x 版本中 Corefile 部分更新了点东西，使用如下替换整个 Corefile 部分

```
# vi coredns.yaml

...
data:
  Corefile: |
    .:53 {
        errors
        health
        kubernetes cluster.local 10.254.0.0/18 {
          pods insecure
          upstream
          fallthrough in-addr.arpa ip6.arpa
        }
        prometheus :9153
        proxy . /etc/resolv.conf
        cache 30
        loop
        reload
        loadbalance
    }
...        
  clusterIP: 10.254.0.2
```

```
# 配置说明 


# 这里 kubernetes cluster.local 为 创建 svc 的 IP 段

kubernetes cluster.local 10.254.0.0/18 

# clusterIP  为 指定 DNS 的 IP

clusterIP: 10.254.0.2
```
#### 导入 yaml 文件

```
kubectl apply -f coredns.yaml 
```
### 部署 DNS 自动伸缩
按照 node 数量 自动伸缩 dns 数量

```
vi dns-auto-scaling.yaml



kind: ServiceAccount
apiVersion: v1
metadata:
  name: kube-dns-autoscaler
  namespace: kube-system
  labels:
    addonmanager.kubernetes.io/mode: Reconcile
---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: system:kube-dns-autoscaler
  labels:
    addonmanager.kubernetes.io/mode: Reconcile
rules:
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["list"]
  - apiGroups: [""]
    resources: ["replicationcontrollers/scale"]
    verbs: ["get", "update"]
  - apiGroups: ["extensions"]
    resources: ["deployments/scale", "replicasets/scale"]
    verbs: ["get", "update"]
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "create"]
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: system:kube-dns-autoscaler
  labels:
    addonmanager.kubernetes.io/mode: Reconcile
subjects:
  - kind: ServiceAccount
    name: kube-dns-autoscaler
    namespace: kube-system
roleRef:
  kind: ClusterRole
  name: system:kube-dns-autoscaler
  apiGroup: rbac.authorization.k8s.io

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kube-dns-autoscaler
  namespace: kube-system
  labels:
    k8s-app: kube-dns-autoscaler
    kubernetes.io/cluster-service: "true"
    addonmanager.kubernetes.io/mode: Reconcile
spec:
  selector:
    matchLabels:
      k8s-app: kube-dns-autoscaler
  template:
    metadata:
      labels:
        k8s-app: kube-dns-autoscaler
      annotations:
        scheduler.alpha.kubernetes.io/critical-pod: ''
    spec:
      priorityClassName: system-cluster-critical
      containers:
      - name: autoscaler
        image: jicki/cluster-proportional-autoscaler-amd64:1.1.2-r2
        resources:
            requests:
                cpu: "20m"
                memory: "10Mi"
        command:
          - /cluster-proportional-autoscaler
          - --namespace=kube-system
          - --configmap=kube-dns-autoscaler
          - --target=Deployment/coredns
          - --default-params={"linear":{"coresPerReplica":256,"nodesPerReplica":16,"preventSinglePointFailure":true}}
          - --logtostderr=true
          - --v=2
      tolerations:
      - key: "CriticalAddonsOnly"
        operator: "Exists"
      serviceAccountName: kube-dns-autoscaler
```

```
kubectl apply -f dns-auto-scaling.yaml
```
### 部署 traefik
#### 创建证书

```
#master1
mkdir /etc/kubernetes/cert/
cd /etc/kubernetes/cert/

openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout traefik-ui.startdt.me-key.key -out traefik-ui.startdt.me.pem -subj "/CN=traefik-ui.startdt.me"

kubectl create secret tls traefik-tls --namespace=kube-system --cert traefik-ui.startdt.me.pem --key traefik-ui.startdt.me-key.key
```
#### 创建configmap

```
#master1 

mkdir /etc/kubernetes/conf/

vi traefik.toml 

defaultEntryPoints = ["http","https"]
[entryPoints]
  [entryPoints.http]
  address = ":80"
    entryPoint = "https"
  [entryPoints.https]
  address = ":443"
    [entryPoints.https.tls]
      [[entryPoints.https.tls.certificates]]
      certFile = "/cert/dashboard.startdt.me.pem"
      keyFile = "/cert/dashboard.startdt.me-key.key"
      [[entryPoints.https.tls.certificates]]
      certFile = "/cert/nginx.startdt.me.pem"
      keyFile = "/cert/nginx.startdt.me-key.key"
      [[entryPoints.https.tls.certificates]]
      certFile = "/cert/traefik-ui.startdt.me.pem"
      keyFile = "/cert/traefik-ui.startdt.me-key.key"
```

```
#创建
kubectl create configmap traefik-conf --from-file=traefik.toml -n kube-system
```

#### 配置文件

```
mkdir /etc/kubernetes/traefik/new

#cat ingress-rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ingress
  namespace: kube-system
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
  name: ingress
subjects:
  - kind: ServiceAccount
    name: ingress
    namespace: kube-system
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io


#cat traefik-ingress.yaml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: traefik-ingress-lb
  namespace: kube-system
  labels:
    k8s-app: traefik-ingress-lb
spec:
  replicas: 2
  template:
    metadata:
      labels:
        k8s-app: traefik-ingress-lb
        name: traefik-ingress-lb
    spec:
      terminationGracePeriodSeconds: 60
      hostNetwork: true
      restartPolicy: Always
      serviceAccountName: ingress
      nodeSelector:
        ingress: proxy
      volumes:
      - name: ssl
        hostPath:
          path: /etc/kubernetes/cert
      - name: config
        configMap:
          name: traefik-conf
      containers:
      - image: traefik
        name: traefik-ingress-lb
        volumeMounts:
        - mountPath: "/ssl"
          name: "ssl"
        - mountPath: "/config"
          name: "config"
        resources:
          limits:
            cpu: 200m
            memory: 30Mi
          requests:
            cpu: 100m
            memory: 20Mi
        ports:
        - containerPort: 80
        - containerPort: 443
        - containerPort: 8580
        args:
        - --web.address=:8580
        - --web
        - --kubernetes
        - --configfile=/config/traefik.toml
---
kind: Service
apiVersion: v1
metadata:
  name: traefik
  namespace: kube-system
spec:
  type: NodePort
  ports:
  - protocol: TCP
    port: 80
    name: http
  - protocol: TCP
    port: 443
    name: https
  selector:
    k8s-app: traefik-ingress-lb


#cat traefik_ui.yaml 
apiVersion: v1
kind: Service
metadata:
  name: traefik-web-ui
  namespace: kube-system
spec:
  type: NodePort
  selector:
    k8s-app: traefik-ingress-lb
  ports:
  - name: web
    port: 80
    targetPort: 8580
---
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: traefik-web-ui
  namespace: kube-system
spec:
  tls:
  - secretName: traefik-tls
  rules:
  - host: traefik-ui.startdt.me
    http:
      paths:
      - path: /
        backend:
          serviceName: traefik-web-ui
          servicePort: web
```

### 部署 Metrics
#### 生成证书

```
#master1
cd /opt/ssl/
vi front-proxy-ca-csr.json

{
    "CN": "kubernetes",
    "key": {
        "algo": "rsa",
        "size": 2048
    }
}


vi front-proxy-client-csr.json

{
    "CN": "front-proxy-client",
    "key": {
        "algo": "rsa",
        "size": 2048
    }
}


 cfssl gencert   -initca front-proxy-ca-csr.json | cfssljson -bare front-proxy-ca
 
 cfssl gencert -ca=/opt/ssl/front-proxy-ca.pem -ca-key=/opt/ssl/front-proxy-ca-key.pem -config=/opt/ssl/config.json -profile=kubernetes front-proxy-client-csr.json |cfssljson -bare front-proxy-client
 
 cp front-proxy* /etc/kubernetes/ssl/
 scp front-proxy* master2:/etc/kubernetes/ssl/
 scp front-proxy* node1:/etc/kubernetes/ssl/
```
#### 修改kube-apiserver

```
#master1/2
vi /etc/systemd/system/kube-apiserver.service 

#添加vo

  --requestheader-client-ca-file=/etc/kubernetes/ssl/front-proxy-ca.pem \
  --requestheader-allowed-names=aggregator \
  --requestheader-extra-headers-prefix=X-Remote-Extra- \
  --requestheader-group-headers=X-Remote-Group \
  --requestheader-username-headers=X-Remote-User \
  --proxy-client-cert-file=/etc/kubernetes/ssl/front-proxy-client.pem \
  --proxy-client-key-file=/etc/kubernetes/ssl/front-proxy-client-key.pem \
  --runtime-config=api/all=true \
  --enable-aggregator-routing=true \
```

```
systemctl daemon-reload
systemctl  restart kube-apiserver.service
```
#### 部署metrics-server

```
git clone https://github.com/kubernetes-incubator/metrics-server
```

```
#修改配置文件
cd metrics-server/deploy/1.8+/

vi metrics-server-deployment.yaml
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: metrics-server
  namespace: kube-system
---
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: metrics-server
  namespace: kube-system
  labels:
    k8s-app: metrics-server
spec:
  selector:
    matchLabels:
      k8s-app: metrics-server
  template:
    metadata:
      name: metrics-server
      labels:
        k8s-app: metrics-server
    spec:
      serviceAccountName: metrics-server
      volumes:
      # mount in tmp so we can safely use from-scratch images and/or read-only containers
      - name: tmp-dir
        emptyDir: {}
      #增加
      - name: ca-ssl
        hostPath:
          path: /etc/kubernetes/ssl
      containers:
      - name: metrics-server
        #修改镜像源
        image: jicki/metrics-server-amd64:v0.3.1
        imagePullPolicy: Always
        #增加
        command:
        - /metrics-server
        - --kubelet-insecure-tls
        - --requestheader-client-ca-file=/opt/ssl/front-proxy-ca.pem
        - --kubelet-preferred-address-types=InternalIP
        volumeMounts:
        - name: tmp-dir
          mountPath: /tmp
        增加
        - mountPath: /opt/ssl
          name: ca-ssl
```

```
#创建
 kubectl apply -f .
 
 kubectl top pod
 kubectl top node
```
