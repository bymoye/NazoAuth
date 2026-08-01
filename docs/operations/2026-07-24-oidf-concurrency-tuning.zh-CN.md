# 2026-07-24 OIDF 并发调优记录

本记录验证
[全新环境部署与生产启用](fresh-production-activation.zh-CN.md)
中的 OIDC/FAPI 与 OpenID4VC 调度组合。目标不是无上限提高并发，而是在当前远端
主机上缩短总墙钟，同时保留账号、浏览器、suite 源码和清理边界。

## 验证边界

| 项目 | 值 |
| --- | --- |
| 已部署应用提交 | `decb71c8b711d40836b5189580358190cabce9b2` |
| 调度 runner 提交 | `915488304216f03a279c725f81fdbf8d4064b005` |
| OIDF suite revision | `946451d1ce29965c9ab7aee05f5003552233160e` |
| 应用镜像 | `localhost/nazo-oauth-server:modular-decb71c-web-4c7530b` |
| 镜像 ID | `1492ab05ac833fec9670b7be708c2685c75ed340c1091680c20482c0275940c1` |
| 主机资源 | 8 vCPU、约 32 GiB 内存 |

runner 与已部署应用 revision 被分别校验；本记录不把 runner revision 描述为
线上应用 revision。调优过程没有重建或替换 2026-07-23 全新启用时创建的生产
数据库。

## 分档结果

### OpenID4VC

| 运行 | 计划分组 | 墙钟 | suite 内存峰值 | load 峰值 | 结果 |
| --- | --- | ---: | ---: | ---: | --- |
| `e76-decb71c8-0724a-vci-g4` | `4+4+4+4+1` | 9:43 | 2454 MiB | 2.08 | 386 PASSED、3 SKIPPED |
| `e77-decb71c8-0724b-vci-g8` | `8+8+1` | 8:17 | 2458 MiB | 3.12 | 386 PASSED、3 SKIPPED |
| `e79-decb71c8-0724d-vci-g17` | `17` | 5:27 | 2465 MiB | 2.36 | 386 PASSED、3 SKIPPED |

三档均为 17 个计划、389 个模块、0 失败，证据 manifest 中没有缺失签名。17
计划同批没有增加内存峰值，却比 8 计划批次再缩短约 34%，因此选择
`--plan-group-size 17`。

### OIDC/FAPI

OIDC runner 把 27 个计划划分为三个阶段：

1. `01`、`02`、`04`-`07` 是可并行安全组；
2. `03a`-`03d` 共享 CIBA 申请人和轮询/回调时序，保持串行；
3. `08`-`11` 以两个外层 worker 执行，每组内部保持 `--no-parallel`。

| 运行 | 安全组 worker | 浏览器组 worker | 墙钟 | suite CPU | suite 内存峰值 | load 峰值 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `e78-decb71c8-0724c-oidc-w2` | 2 | 2 | 18:18 | 约 338 秒 | 2340 MiB | 4.43 |
| `e80-decb71c8-0724e-oidc-w4` | 4 | 2 | 15:42 | 约 640 秒 | 4652 MiB | 7.18 |

两档均为 27 个计划、800 个模块：775 PASSED、17 个既有审核边界内的 REVIEW、
8 SKIPPED、0 失败，证据签名无缺失。4-worker 只再缩短约 14%，suite CPU 和
内存却约翻倍，并接近 8 vCPU 上限。因此联合生产闸门选择
`--safe-group-workers 2 --browser-group-workers 2`，4-worker 仅作为资源充足且
只运行 OIDC 时的速度档，不是资源效率档。

## 最终联合组合

最终运行使用：

- OIDC/FAPI：安全组 2 worker、CIBA 1 worker、浏览器隔离组 2 worker；
- OpenID4VC：17 个计划同批；
- OIDC 先完成基础 suite 干净检查并创建两个 worktree，之后启动 OpenID4VC；
- 两套矩阵使用不同 run namespace、别名、结果目录和 suite 配置位置。

| 矩阵 | 结果目录 | 计划 | 模块结果 | 退出码 |
| --- | --- | ---: | --- | ---: |
| OIDC/FAPI | `f82-decb71c8-0724g-oidc-w2` | 27 | 775 PASSED、17 REVIEW、8 SKIPPED；800 总计 | 0 |
| OpenID4VC | `f82-decb71c8-0724g-vci-g17` | 17 | 386 PASSED、3 SKIPPED；389 总计 | 0 |

联合资源窗口为 `2026-07-24T03:34:54Z` 至 `03:52:52Z`，总墙钟 17:58；
load 峰值 6.22，最低可用内存 21199 MiB，suite 内存峰值 4657 MiB。该总墙钟
比两套所选单矩阵串行运行的 23:45 缩短约 24%，同时低于 OIDC 4-worker
单独运行的 load 峰值。

两套矩阵都完成即时检查和 45 秒稳定检查。最终基础 suite、OIDC 临时
worktree、runner 源码和已部署源码均为干净工作区；没有活动 conformance
runner。生产 `/health` 正常，发现文档 issuer 仍为 `https://auth.nazo.run`，
`/ui/auth` 返回 200。

## 启动顺序发现

第一次联合协调尝试 `f81` 先启动 OpenID4VC。OIDC 在创建任何测试模块前以
`official conformance-suite source tree must be clean` 拒绝启动，因为基础 suite
此时已有 OpenID4VC 临时配置。OpenID4VC 本身正常退出 0，并由新 runner 自动
删除全部 17 个生成配置。

这次预检失败没有被忽略或改写为 expected failure。最终流程改为 OIDC-first：
先让 OIDC 校验干净基础 suite 并创建独立 worktree，再启动使用基础 suite 的
OpenID4VC。`f82` 验证了该顺序及其清理边界。

## 保留的串行边界

CIBA 仍保持串行。要继续压缩这一阶段，必须先为四个 CIBA lane 提供独立测试
账号、登录提示、会话和决策状态命名空间，再单独验证；不得直接让当前共享账号的
四组并行。机器资源尚有余量不等于协议状态已隔离。
