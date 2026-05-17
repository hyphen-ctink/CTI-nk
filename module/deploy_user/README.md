# CTI-nk deploy_user

사용자 Linux host 위에서 `backend-container`, `db-container`, `user-container`를 실행하는 배포 패키지다.
참고) backend-container는 아직 완료되지 않아, detection_rule_deployer.py로만 테스트를 진행하였다.


## 1. 공유 구조

```text
backend-container                         user-container

/shared/rules/snort    <-------------->   /etc/snort/rules
/shared/rules/yara     <-------------->   /opt/ctink/yara/rules

/shared/logs/snort     <-------------->   /var/log/snort
/shared/logs/yara      <-------------->   /var/log/ctink
```

```text
사용자 Linux host                         user-container

/home/<USER>/Downloads  -------------->   /scan_target/downloads
```

`db-container`는 DB 저장소만 담당한다. 룰 파일, IDS 로그, Downloads 경로를 직접 공유하지 않는다.

## 2. 실행 전 준비

필요한 것:

```text
- Linux host
- Docker
- Docker Compose
- ctink-backend:latest 이미지
```

현재 `docker-compose.yml`은 backend 이미지를 다음 이름으로 사용한다.

```text
ctink-backend:latest
```

최종적인 백엔드 이미지 이름이 다르면 `docker-compose.yml`의 `backend-container.image` 값을 바꾸면 된다.

## 3. 설치 및 실행 (deploy_user 디렉토리에서)

```bash
chmod +x install.sh
./install.sh
```

`install.sh`는 다음을 자동으로 처리한다.

```text
- 실제 사용자 home directory 확인
- /home/<USER>/Downloads 생성
- .env 생성
- Docker named volume 생성
- 기본 룰/log 파일 생성
- docker compose up -d --build 실행
```

컨테이너 확인:

```bash
docker compose ps
```

로그 확인:

```bash
docker logs -f ctink-user
```

## 4. .env 설정

설치 후 `.env`가 자동 생성된다.

기본값:

```env
HOST_DOWNLOADS_DIR=/home/<USER>/Downloads
SNORT_INTERFACE=auto
RULE_WATCH_INTERVAL_SEC=10
YARA_SCAN_INTERVAL_SEC=30
```

`SNORT_INTERFACE=auto`는 컨테이너 내부 default route를 보고 실제 인터페이스를 자동 탐지한다.

`any`는 쓰지 않는다. 일부 Snort 환경에서 다음 오류가 날 수 있기 때문.

```text
Cannot decode data link type 113
```

자동 탐지가 잘 작동되지 않으면 아래처럼 직접 지정한다.

```env
SNORT_INTERFACE=eth0
```

또는:

```env
SNORT_INTERFACE=ens33
```

변경 후 재시작:

```bash
docker compose up -d --build --force-recreate user-container
```

## 5. 경로 확인

Snort 룰 공유 확인:

```bash
docker exec -it ctink-backend ls -al /shared/rules/snort
docker exec -it ctink-user ls -al /etc/snort/rules
```

YARA 룰 공유 확인:

```bash
docker exec -it ctink-backend ls -al /shared/rules/yara
docker exec -it ctink-user ls -al /opt/ctink/yara/rules
```

Snort 로그 공유 확인:

```bash
docker exec -it ctink-backend ls -al /shared/logs/snort
docker exec -it ctink-user ls -al /var/log/snort
```

YARA 로그 공유 확인:

```bash
docker exec -it ctink-backend ls -al /shared/logs/yara
docker exec -it ctink-user ls -al /var/log/ctink
```

Downloads 공유 확인:

```bash
docker exec -it ctink-user ls -al /scan_target/downloads
```

## 6. Snort 실행 확인

Snort 프로세스 확인:

```bash
docker exec -it ctink-user ps -ef | grep '[s]nort'
```

실제 Snort 실행 명령 확인:

```bash
docker exec -it ctink-user sh -lc 'PID=$(pgrep -n snort); tr "\0" " " < /proc/$PID/cmdline; echo'
```

정상 예시:

```text
snort -A fast -q -c /etc/snort/snort.conf -i eth0 -l /var/log/snort
```

rule watcher 로그 확인:

```bash
docker exec -it ctink-user tail -n 100 /var/log/ctink/rule_watcher.log
```

자동 인터페이스 탐지가 정상이라면 이런 로그가 나온다.

```text
[rule_watcher] SNORT_INTERFACE env: auto
[snort] SNORT_INTERFACE=auto, detected interface: eth0
```

Snort 자체 로그 확인:

```bash
docker exec -it ctink-user tail -n 100 /var/log/ctink/snort_process.log
```

## 7. Snort 룰 테스트

backend-container 안에서 룰 추가:

```bash
docker exec ctink-backend python3 /app/detection_rule_deployer.py apply --json '{
  "rule_type": "snort",
  "rule_content": "alert icmp any any -> any any (msg:\"CTINK ICMP TEST\"; sid:1000001; rev:1;)"
}'
```

룰 공유 확인:

```bash
docker exec -it ctink-backend cat /shared/rules/snort/local.rules
docker exec -it ctink-user cat /etc/snort/rules/local.rules
```

호스트에서 테스트 트래픽 발생:

```bash
ping -c 3 8.8.8.8
```

Snort alert 확인:

```bash
docker exec -it ctink-user tail -n 50 /var/log/snort/alert
docker exec -it ctink-backend tail -n 50 /shared/logs/snort/alert
```


## 8. YARA 룰 테스트

backend-container 안에서 룰 추가:

```bash
docker exec ctink-backend python3 /app/detection_rule_deployer.py apply --json '{
  "rule_type": "yara",
  "rule_content": "rule CTINK_YARA_TEST { strings: $a = \"CTINK_YARA_TEST_STRING\" condition: $a }"
}'
```

룰 공유 확인:

```bash
docker exec -it ctink-backend cat /shared/rules/yara/ctink_rules.yar
docker exec -it ctink-user cat /opt/ctink/yara/rules/ctink_rules.yar
```

Downloads에 테스트 파일 생성:

```bash
echo "hello CTINK_YARA_TEST_STRING" > "$HOME/Downloads/ctink_yara_test.txt"
```

컨테이너에서 보이는지 확인:

```bash
docker exec -it ctink-user cat /scan_target/downloads/ctink_yara_test.txt
```

스캔 주기만큼 기다린 뒤 확인:

```bash
sleep 35
docker exec -it ctink-user tail -n 50 /var/log/ctink/yara_scan.log
docker exec -it ctink-backend tail -n 50 /shared/logs/yara/yara_scan.log
```

## 9. 룰 삭제 테스트

Snort 룰 삭제:

```bash
docker exec ctink-backend python3 /app/detection_rule_deployer.py remove --json '{
  "rule_type": "snort",
  "rule_content": "alert icmp any any -> any any (msg:\"CTINK ICMP TEST\"; sid:1000001; rev:1;)"
}'
```

YARA 룰 삭제:

```bash
docker exec ctink-backend python3 /app/detection_rule_deployer.py remove --json '{
  "rule_type": "yara",
  "rule_content": "rule CTINK_YARA_TEST { strings: $a = \"CTINK_YARA_TEST_STRING\" condition: $a }"
}'
```

## 10. 테스트용 backend 이미지

백엔드 이미지가 아직 없으면 `backend-test/`를 이용해서 임시 backend 이미지를 만들 수 있다.

```bash
cd backend-test
cp /path/to/detection_rule_deployer.py ./detection_rule_deployer.py
docker build -t ctink-backend:latest .
cd ..
```

그 다음 다시 실행한다.

```bash
docker compose up -d --build
```
