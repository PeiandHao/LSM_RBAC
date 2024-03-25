cmd_/home/peiwithhao/repo/LSM_RBAC/lsm_module.mod := printf '%s\n'   lsm_module.o | awk '!x[$$0]++ { print("/home/peiwithhao/repo/LSM_RBAC/"$$0) }' > /home/peiwithhao/repo/LSM_RBAC/lsm_module.mod
