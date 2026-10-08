#!/bin/bash
echo "========================================"
echo "  ztacloud DR Site Health Check"
echo "========================================"
echo ""
ssh -i ~/.ssh/zta_gcp ztacloud@100.111.196.121 "bash ~/start-ztacloud.sh"
