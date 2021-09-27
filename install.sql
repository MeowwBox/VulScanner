INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (1, 'burp_sql_pwd', '数据库弱密码', '弱密码', 'danger', 0, 1, '');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (2, 'shiro_deserialize', 'shiro反序列化', '命令执行', 'danger', 0, 1, '');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (3, 'burp_tomcat', 'Tomcat弱密码', '弱密码', 'danger', 1, 0, '执行命令');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (7, 'inspur_rce', '浪潮管理系统RCE', '命令执行', 'danger', 1, 0, '执行命令');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (8, 'nc_bsh_rce', '用友OA BshServlet接口泄露', '命令执行', 'danger', 1, 0, '执行命令');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (9, 'sangfor_safe_rce', '深信服行为感知系统RCE', '命令执行', 'danger', 1, 0, '执行命令');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (10, 'safe_md5_pwd', '安全设备md5密码泄露', '弱密码', 'danger', 0, 0, '');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (13, 'docker', 'docker未授权', '命令执行', 'danger', 0, 0, '');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (14, 'thinkphp_debug', 'Thinkphp debug命令执行', '命令执行', 'danger', 1, 0, '执行命令');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (15, 'thinkphp5_rce', 'Thinkphp5命令执行', '命令执行', 'danger', 1, 0, '上传文件');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (16, 'wui_sql', '泛微OA8.0 前台SQL注入', 'SQL注入', 'warning', 0, 0, '');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (17, 'wui_file', '泛微OA9.0 任意文件上传', '任意文件上传', 'danger', 0, 0, '');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (18, 'weblogic_pwd', 'weblogic控制台弱密码', '弱密码', 'danger', 0, 0, '');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (19, 'weblogic_xml', 'weblogic_XML反序列化', '命令执行', 'danger', 1, 0, '上传文件');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (20, 'weblogic_wls9', 'weblogic_wls9-async反序列化', '命令执行', 'danger', 1, 0, '执行命令');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (21, 'weblogic_console_unauthorize', 'weblogic_控制台未授权访问', '垂直越权', 'warning', 0, 0, '');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (22, 'seeyon_webmail', '致远OA_webmail.do任意文件下载', '任意文件读取', 'warning', 1, 0, '读取文件');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (23, 'showdoc', 'ShowDoc 任意文件上传', '任意文件上传', 'danger', 1, 0, '上传文件');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (24, 'ms17_010', 'MS17_010', '命令执行', 'danger', 0, 0, '');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (25, 'jumpserver_logs', 'JumpServer 日志接口未授权', '垂直越权', 'warning', 0, 0, '');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (26, 'apache_solr_file', 'Apache Solr 任意文件读取', '任意文件读取', 'warning', 1, 0, '读取文件');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (28, 'fineport_v8_file', '帆软报表V8.0 任意文件读取', '任意文件读取', 'warning', 1, 0, '读取文件');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (29, 'minio_ssrf', 'MinIO SSRF', 'SSRF', 'warning', 0, 0, '');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (30, 'apache_flink_file', 'Apache Flink 任意文件读取', '任意文件读取', 'warning', 1, 0, '读取文件');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (31, 'zyxel_user', 'Zyxel 硬编码后门账户', '弱密码', 'danger', 0, 0, '');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (33, 'burp_ssh', 'ssh弱密码', '弱密码', 'danger', 1, 0, '执行命令');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (34, 'apache_solr_velocity', 'Apache Solr Velocity模板远程执行', '命令执行', 'danger', 1, 0, '执行命令');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (35, 'landary_file', '蓝凌OA 任意文件读取', '任意文件读取', 'danger', 1, 0, '读取文件');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (36, 'daloradius_pwd', 'daloradius弱密码', '弱密码', 'danger', 1, 0, '上传文件');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (37, 'wui_xml', '泛微OA_XML反序列化', '命令执行', 'danger', 0, 0, '');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (38, 'nete_firewall', '奇安信 网康下一代防火墙RCE', '命令执行', 'danger', 1, 0, '执行命令');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (39, 'vesystem_rce', '和信创天云桌面_RCE', '任意文件上传', 'danger', 1, 0, '上传文件');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (40, 'tianqin_sql', '360天擎 前台SQL注入', 'SQL注入', 'danger', 0, 0, '');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (41, 'h3c_secparth_rce', 'H3C SecParh堡垒机远程命令执行', '命令执行', 'danger', 1, 0, '执行命令');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (42, 'axis2_password', 'axis2弱密码', '弱密码', 'danger', 1, 0, '执行命令');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (43, 'node_red_file', 'Node-RED 任意文件读取', '任意文件读取', 'danger', 1, 0, '读取文件');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (48, 'lanproxy_file', 'LanProxy 任意文件读取', '任意文件读取', 'danger', 1, 0, '读取文件');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (49, 'XenMobile_file', 'Citrix XenMobile 任意文件读取', '任意文件读取', 'warning', 1, 0, '读取文件');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (50, 'jinher_pwd', '金和OA C6 管理员默认口令', '弱密码', 'warning', 0, 0, '');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (51, 'vsphere_rce', 'vSphere Client RCE', '命令执行', 'danger', 1, 0, '执行命令');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (52, 'zentao_sql', '禅道 V8.2-9.2.1 sql注入', 'SQL注入', 'danger', 1, 0, '上传文件');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (53, 'zentao_rce', '禅道 11.6 远程命令执行', '命令执行', 'warning', 0, 0, '上传文件');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (54, 'qizhi_user', '齐治堡垒机 任意用户登录漏洞', '垂直越权', 'warning', 0, 0, '');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (55, 'kyan_pwd', 'Kyan 网络监控设备 密码泄露', '弱密码', 'danger', 1, 0, '执行命令');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (56, 'xxl_job_pwd', 'XXL-JOB任务调度中心 默认密码', '弱密码', 'danger', 0, 0, '');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (57, 'panabit_pwd', 'Panabit智能应用网关 弱密码', '弱密码', 'danger', 1, 0, '执行命令');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (58, 'activemq_pwd', 'Apache ActiveMQ 弱密码', '弱密码', 'warning', 0, 0, '');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (59, 'zhongxin_pwd', '中新金盾信息安全管理系统 默认密码', '弱密码', 'danger', 0, 0, '');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (60, 'ruijie_admin', '锐捷EG易网关 管理员账号密码泄露', '命令执行', 'danger', 1, 0, '执行命令');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (61, 'nacos_unauthorize', 'Alibaba Nacos 未授权访问', '垂直越权', 'danger', 0, 0, '');
INSERT INTO `scan`.`pocmodel_poc`(`id`, `poc_name`, `real_name`, `type`, `risk`, `hasExp`, `isUse`, `cmd`) VALUES (63, 'icewarp_rce', 'IceWarp WebClient  远程命令执行', '命令执行', 'danger', 1, 1, '执行命令');
INSERT INTO `usermodel_user`(`id`, `username`, `password`) VALUES (1, 'admin', 'admin');
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("深信服产品", "sangfor", "sangfor");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("深信服产品", "sangfor", "sangfor@2018");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("深信服产品", "sangfor", "sangfor@2019");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("深信服科技 AD", "sangfor", "dlanrecover");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("深信服负载均衡 AD 3.6", "admin", "admin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("深信服WAC ( WNS V2.6)", "admin", "admin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("深信服VPN", "Admin", "Admin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("深信服ipsec-VPN (SSL 5.5)", "Admin", "Admin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("深信服AC6.0", "admin", "admin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("SANGFOR防火墙", "admin", "sangfor");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("深信服AF(NGAF V2.2)", "admin", "sangfor");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("深信服NGAF下一代应用防火墙(NGAF V4.3)", "admin", "admin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("深信服AD3.9", "admin", "admin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("深信服上网行为管理设备数据中心", "Admin", "密码为空");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("SANGFOR_AD_v5.1", "admin", "admin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("网御漏洞扫描系统", "leadsec", "leadsec");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("天阗入侵检测与管理系统 V7.0", "Admin", "venus70");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("天阗入侵检测与管理系统 V7.0", "Audit", "venus70");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("天阗入侵检测与管理系统 V7.0", "adm", "venus70");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("天阗入侵检测与管理系统 V6.0", "Admin", "venus60");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("天阗入侵检测与管理系统 V6.0", "Audit", "venus60");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("天阗入侵检测与管理系统 V6.0", "adm", "venus60");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("网御WAF集中控制中心(V3.0R5.0)", "admin", "leadsec.waf");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("网御WAF集中控制中心(V3.0R5.0)", "audit", "leadsec.waf");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("网御WAF集中控制中心(V3.0R5.0)", "adm", "leadsec.waf");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("联想网御", "administrator", "administrator");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("网御事件服务器", "admin", "admin123");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("联想网御防火墙PowerV", "administrator", "administrator");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("联想网御入侵检测系统", "lenovo", "default");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("网络卫士入侵检测系统", "admin", "talent");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("网御入侵检测系统V3.2.72.0", "adm", "leadsec32");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("网御入侵检测系统V3.2.72.0", "admin", "leadsec32");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("联想网御入侵检测系统IDS", "root", "111111");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("联想网御入侵检测系统IDS", "admin", "admin123");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("科来网络回溯分析系统", "csadmin", "colasoft");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("中控考勤机web3.0", "administrator", "123456");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("H3C iMC", "admin", "admin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("H3C SecPath系列", "admin", "admin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("H3C S5120-SI", "test", "123");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("H3C智能管理中心", "admin", "admin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("H3C ER3100", "admin", "adminer3100");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("H3C ER3200", "admin", "adminer3200");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("H3C ER3260", "admin", "adminer3260");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("H3C", "admin", "adminer");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("H4C", "admin", "admin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("H5C", "admin", "h3capadmin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("H6C", "h3c", "h3c");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("360天擎", "admin", "admin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("网神防火墙", "firewall", "firewall");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("天融信防火墙NGFW4000", "superman", "talent");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("黑盾防火墙", "admin", "admin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("黑盾防火墙", "rule", "abc123");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("黑盾防火墙", "audit", "abc123");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("华为防火墙", "telnetuser", "telnetpwd");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("华为防火墙", "ftpuser", "ftppwd");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("方正防火墙", "admin", "admin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("飞塔防火墙", "admin", "密码为空");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("Juniper_SSG__5防火墙", "netscreen", "netscreen");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("中新金盾硬件防火墙", "admin", "123");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("kill防火墙(冠群金辰)", "admin", "sys123");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("华为天清汉马USG防火墙", "admin", "venus.fw");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("华为天清汉马USG防火墙", "Audit", "venus.audit");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("华为天清汉马USG防火墙", "useradmin", "venus.user");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("阿姆瑞特防火墙", "admin", "manager");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("山石网科", "hillstone", "hillstone");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("绿盟安全审计系统", "weboper", "weboper");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("绿盟安全审计系统", "webaudit", "webaudit");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("绿盟安全审计系统", "conadmin", "conadmin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("绿盟安全审计系统", "admin", "admin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("绿盟安全审计系统", "shell", "shell");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("绿盟产品", "", "nsfocus123");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("TopAudit日志审计系统", "superman", "talent");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("LogBase日志管理综合审计系统", "admin", "safetybase");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("网神SecFox运维安全管理与审计系统", "admin", "!1fw@2soc#3vpn");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("天融信数据库审计系统", "superman", "telent");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("Hillstone安全审计平台", "hillstone", "hillstone");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("网康日志中心", "ns25000", "ns25000");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("网络安全审计系统（中科新业）", "admin", "123456");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("天玥网络安全审计系统", "Admin", "cyberaudit");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("明御WEB应用防火墙", "admin", "admin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("明御WEB应用防火墙", "admin", "adminadmin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("明御攻防实验室平台", "root", "123456");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("明御安全网关", "admin", "adminadmin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("明御运维审计与册风险控制系统", "admin", "1q2w3e");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("明御运维审计与册风险控制系统", "system", "1q2w3e4r");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("明御运维审计与册风险控制系统", "auditor", "1q2w3e4r");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("明御运维审计与册风险控制系统", "operator", "1q2w3e4r");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("明御网站卫士", "sysmanager", "sysmanager888");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("亿邮邮件网关", "eyouuser", "eyou_admin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("亿邮邮件网关", "eyougw", "admin@(eyou)");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("亿邮邮件网关", "admin", "+-ccccc");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("亿邮邮件网关", "admin", "cyouadmin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("Websense邮件安全网关", "administrator", "admin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("梭子鱼邮件存储网关", "admin", "admin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("华天动力OA系统", "user", "123456");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("华三H3C设备", "admin", "h3capadmin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("华为设备", "admin", "admin@huawei");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("华为设备", "admin", "admin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("华为ODN", "admin", "Admin_123");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("深信服设备", "sangfor", "sangfor");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("深信服设备", "sangfor", "sangfor@2018");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("深信服设备", "sangfor", "sangfor@2019");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("Ixcache", "admin", "ixcache");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("天波telpo路由器", "admin", "admin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("全向QL1680路由器", "admin", "qxcomm1680");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("全向QL1680路由器", "admin", "qxcommsupport");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("全向QL1880路由器", "root", "root");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("全向QL1688路由器 ", "admin", "qxcomm1688");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("全向qxcomm1680", "qxcomm", "qxcomm1680");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("全向qxcomm1688", "qxcomm", "qxcommsuport");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("TP-LINKTD-8800", "【ie上输入】admin", "admin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("合勤zyxel642telnet", "【ie上输入】admin", "1234");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("EcomED-802EG", "root", "root");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("神州数码6010RA", "ADSL", "ADSL1234");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("华为SmartAXMT800", "admin", "admin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("伊泰克", "supervisor", "12345");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("华硕", "adsl", "adsl1234");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("华硕", "adsl", "阿尔卡特");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("同维DSL699E", "ROOT", "ROOT");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("大亚DB102", "admin", "dare");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("WST的RT1080", "root", "root");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("WST的ART18CX", "admin", "conexant");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("实达ADSL2110-EH", "admin", "starnetadsl");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("泛德用户", "admin", "conexant");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("泛德用户", "admin", "东信Ea700");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("broadmax的hsa300a", "broadmax", "broadmax");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("长虹ch-500E", "root", "root");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("重庆普天CPADSL03", "root", "root");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("重庆普天CPADSL03", "root", "台湾突破EA110RS232:38400");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("etek-td的ADSL_T07L006.0", "supervisor", "12345");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("GVC的DSL-802E/R3A", "admin", "epicrouter");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("sunrise的SR-DSL-AE", "admin", "0000");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("sunrise的DSL-802E_R3", "admin", "epicrouter");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("UTStar的ut-300R", "admin", "utstar");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("湖北邮通", "admin", "epicrouter");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("亨威NSM500网速通", "root", "root");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("艾玛701g", "admin", "admin");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("艾玛701H", "admin", "epicrouter");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("神州数码/华硕", "adsl", "adsl1234");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("普天", "admin", "dare");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("e-tek", "admin", "12345");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("zyxel", "admin", "12345");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("中兴", "adsl", "adsl831");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("华为USG5500", "admin", "Admin@123");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("华为USG5500", "admin", "Admin@123");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("华为USG6300/6500/6600", "admin", "Admin@123");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("华为USG9100", "admin", "Admin@123");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("华为USG9300", "eudemon", "eudemon");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("华为华为USG9300", "admin", "Admin@123");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("华为USG9300", "admin", "Admin@123");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("华为USG9300", "admin", "Admin@123");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("华为USG9500", "admin", "Admin@123");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("华为USG9500", "admin", "Admin@123");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("WAF2000/5000", "admin", "Admin@123");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("IBM Storwize V3700服务助手工具", "superuser", "passw0rd");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("IBM Storwize V3700数据存储服务器管理系统", "superuser", "passw0rd");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("Harbor", "admin", "Harbor12345");
insert into pwdmodel_pwd(`system`, `username`, `password`) values ("arcgis", "siteadmin", "siteadmin");
INSERT INTO `scan`.`groupmodel_group`(`id`, `name`, `webvpn`, `cookies`) VALUES (1, '测试', '', '');
INSERT INTO `scan`.`groupmodel_group`(`id`, `name`, `webvpn`, `cookies`) VALUES (2, 'IP采集', '', '');