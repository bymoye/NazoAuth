# 2026-07-23 全新生产启用记录

本记录是
[全新环境部署与生产启用](fresh-production-activation.zh-CN.md)
的首次实测。生产启用时间为 `2026-07-23T13:21:03Z`。

## 部署对象

| 项目 | 值 |
| --- | --- |
| 后端提交 | `decb71c8b711d40836b5189580358190cabce9b2` |
| 前端提交 | `4c7530b8ccbea1cf7e9fa2d648ac4e233c6757ae` |
| 镜像 | `localhost/nazo-oauth-server:modular-decb71c-web-4c7530b` |
| 镜像 ID | `1492ab05ac833fec9670b7be708c2685c75ed340c1091680c20482c0275940c1` |
| 新数据库 | `oauth_fresh_20260723t111601z` |
| PostgreSQL 卷 | `nazo-oauth-postgres-20260723t111601z` |
| Valkey 卷 | `nazo-oauth-valkey-20260723t111601z` |
| 备份根目录 | `/opt/nazo-oauth/backups/20260723T111601Z` |
| 部署记录 | `decb71c8b711d40836b5189580358190cabce9b2-4c7530b8ccbea1cf7e9fa2d648ac4e233c6757ae-c9cc56b94c7449eea97765206e19a81a.json` |
| OIDF suite revision | `946451d1ce29965c9ab7aee05f5003552233160e` |

旧数据库 dump 和源码归档均在删除前完成验证。旧 PostgreSQL/Valkey 卷保留为
恢复点；`/home/nazoAuth` 已删除且未重新创建。新实例只包含应用数据库
`oauth_fresh_20260723t111601z` 和 `postgres`，已应用 47 个 Diesel migration，
共有 35 张 public 表。

## 全新用户旅程

通过公开注册、登录、资料更新和头像上传完成两名新用户；数据库终态为 2 名用户，
其中 1 名管理员。管理员是在公开注册后通过一次受控角色提升产生，没有直接插入
用户或复制旧库记录。申请人 ID 被显式传给 OpenID4VC operator-black-box
物化流程，没有复用旧模板中的 subject ID。

## 一致性结果

| 矩阵 | 结果目录 | 计划 | 模块结果 | 退出码 |
| --- | --- | ---: | --- | ---: |
| OIDC/FAPI | `r73-decb71c8-0723o-oidc` | 27 | 775 PASSED、17 REVIEW、8 SKIPPED；800 总计 | 0 |
| OpenID4VC | `r75-decb71c8-0723q-vci` | 17 | 386 PASSED、3 SKIPPED；389 总计 | 0 |

两次运行都使用 suite 的既定 REVIEW/SKIPPED 基线，没有新增 expected failure。
OIDC/FAPI 和 OpenID4VC 分别完成 45 秒稳定性复核，product source 与 operator
suite 最终均为完整干净工作区。生产健康接口再次返回正常。

## 实测发现及流程修正

1. 生产 Angie 文件实际位于
   `/usr/local/angie/conf/conf.d/auth.nazo.run.conf`；部署必须显式传入该路径。
2. 新基础设施需要 `postgres` 和 `valkey` network alias，不能只依赖固定 IP。
3. OIDF 运行器必须从精确提交的 `$source_root` 导入，不能硬编码已删除的
   `/home/nazoAuth`。
4. 全新数据库必须先完成公开用户旅程及完整 OIDC profile/address/phone 资料。
5. OpenID4VC onboarding 只在本次确实请求 trust anchor 时要求非空 CA bundle。
6. operator-black-box 物化必须显式接收本次申请人的 `--subject-id`。
7. 工作区洁净度检查必须包括未跟踪文件。r75 生成的 17 个 suite 配置已先归档为
   `r75-openid4vc-suite-generated-configs.tar.gz`，其 SHA-256 为
   `2d205aa1fcd8dc0b35d5b93f97afcfcf1cfd743168514bb7807d7a9a77875ed2`，
   再精确清理；运行器也已增加自动清理。

准备阶段的本地测试/制品、远端备份和只读预检可以并行；两名用户在身份及会话
完全隔离时可以并行。停写、删除、建库、迁移和切流受闸门约束保持串行。
OIDC/FAPI 与 OpenID4VC 共享浏览器、动态客户端和代理状态，因此本次及后续默认
按 `--plan-group-size 1` 串行；只读健康监控、日志哈希和已完成结果汇总可并行。

## 非阻塞遗留项

前端聚合验证全部通过，但 `npm audit` 同时报告 1 个 high 和 1 个 low 的既有依赖
问题。本记录不把它们表述为已修复；应另行完成依赖路径确认和升级验证。
