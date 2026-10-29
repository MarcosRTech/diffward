#!/bin/sh
# ruleid: secret/hardcoded-password
TARGET_URL="$DOMAIN/app/frmLogin.aspx?applicationKey=Zr8vQ2mX7pLk4Tn9Wc3bYh6Ds1Fg0Je5"
# ok: secret/hardcoded-password
TARGET_URL="$DOMAIN/app/frmLogin.aspx?applicationKey=$APPLICATION_KEY"
# ruleid: secret/hardcoded-password
export DEPLOY_TOKEN=gq4Kx9Vt2Mz7Rb3Np8Lw5Hc1
# ruleid: secret/auth-header
curl -H "Authorization: Bearer 9fK2mQx7Lp4Vz8Rt3Wn6Hb1Jc5Yd0Gs" https://api.internal.example/v1/jobs
# ok: secret/auth-header
curl -H "Authorization: Bearer $TOKEN" https://api.internal.example/v1/jobs
