# CTINK 탐지 정책 배포 모듈 사용 가이드

`detection_rule_deployer.py`는 Snort/YARA 탐지 룰을 Ubuntu 시스템에 적용하거나 삭제하는 배포용 파이썬 파일이다.

Snort는 네트워크 트래픽을 상시 탐지함.

YARA는 파일/디렉토리를 주기적으로 스캔해서 탐지함.

---

## 기본 동작

### Snort

Snort 룰 적용 시 코드가 다음 동작을 수행함.

- 룰 파일 경로 생성
- 룰 파일에 Snort 룰 추가
- `/etc/snort/snort.conf`에 룰 파일 include 추가
- `/etc/snort/snort.conf`에 `output alert_fast: alert` 설정 추가
- `/etc/default/snort`에 `ALERTMODE=fast` 설정
    - 이래야 탐지 로그가 생성됨
- `/var/log/snort/alert` 로그 파일 생성
- Snort 서비스 실행 또는 재시작
    - 만약 서비스가 disable 또는 inactive일때
- 실제 탐지 로그를 `/var/log/snort/alert`에 기록

### YARA

YARA 룰 적용 시 코드가 다음 동작을 수행함.

- 룰 파일 경로 생성
- 룰 파일에 YARA 룰 추가
- YARA 룰 파일 목록 등록
- YARA 검사 대상 디렉토리 등록
- YARA scanner 스크립트 생성
    - 스크립트가 존재하지 않는 경우
- `ctink-yara-scanner.service` systemd 서비스 생성
    - 서비스가 disable 또는 inactive 일때
- YARA scanner 서비스 실행
    - 한번 돌려보고 정상 작동 여부를 확인하기 위해
- 실제 탐지 로그를 `/var/log/ctink/yara_scan.log`에 기록하도록 설정

---

## 실행 전 설치

Ubuntu에서 아래 명령어 실행함.

```bash
sudo apt update
sudo apt install -y snort yara python3 python3-pip
```

MQ 방식까지 쓸 경우에만 `pika` 설치함.

```bash
pip install pika
```

CLI 테스트만 할 거면 `pika` 없어도 됨.

---

## 실행 방식

### 정책 적용

```bash
sudo python3 detection_rule_deployer.py apply --input apply.json
```

### 정책 삭제

```bash
sudo python3 detection_rule_deployer.py remove --input remove.json
```

### MQ worker 실행

```bash
python3 detection_rule_deployer.py consume
```

실제 배포/삭제는 `sudo`로 실행해야 함.

`/etc`, `/opt`, `/var`, `systemctl`을 다루기 때문

---

## 입력 JSON 형식

```json
{
  "rule_type": "snort",
  "file_location": "/opt/ctink/snort/ctink.rules",
  "rule_content": "alert icmp any any -> any any (msg:\\"CTINK_SNORT_TEST\\"; sid:1000101; rev:1;)"
}
```

| 필드 | 설명 |
| --- | --- |
| `rule_type` | `snort` 또는 `yara` |
| `file_location` | 룰을 저장할 파일 경로 |
| `rule_content` | 실제 탐지 룰 내용 |

`rule_content`는 필수

`file_location`은 넣는 걸 권장 (그냥 넣자)

`file_location`을 생략하면 기본값을 사용함

| rule_type | 기본 file_location |
| --- | --- |
| `snort` | `/etc/snort/rules/local.rules` |
| `yara` | `/opt/ctink/yara/rules/ctink_rules.yar` |

---

## 출력 형식

### 적용 성공

```json
{
  "status": "success"
}
```

### 삭제 성공

```json
{
  "status": "removed"
}
```

### 적용 실패

```json
{
  "status": "failed to apply",
  "message": "error message"
}
```

### 삭제 실패

```json
{
  "status": "failed to remove",
  "message": "error message"
}
```

---

## Snort 적용 테스트

### 적용 JSON 생성

```bash
cat > snort_apply.json << 'EOF'
{
  "rule_type": "snort",
  "file_location": "/opt/ctink/snort/ctink.rules",
  "rule_content": "alert icmp any any -> any any (msg:\\"CTINK_SNORT_DEPLOY_TEST\\"; sid:1000101; rev:1;)"
}
EOF
```

### 룰 적용

```bash
sudo python3 detection_rule_deployer.py apply --input snort_apply.json
```

정상 출력:

```json
{
  "status": "success"
}
```

### 룰 파일 확인

```bash
sudo grep -n "CTINK_SNORT_DEPLOY_TEST" /opt/ctink/snort/ctink.rules
```

출력되면 룰 파일에 추가된 상태임.

### Snort include 확인

```bash
sudo grep -n "/opt/ctink/snort/ctink.rules" /etc/snort/snort.conf
```

`include /opt/ctink/snort/ctink.rules`가 나오면 정상임.

### Snort 서비스 확인

```bash
sudo systemctl status snort --no-pager
```

`active`면 정상임.

### 탐지 로그 초기화

```bash
sudo mkdir -p /var/log/snort
sudo touch /var/log/snort/alert
sudo truncate -s 0 /var/log/snort/alert
```

### 실제 탐지 트래픽 발생

테스트 룰은 ICMP를 탐지함.

따라서 `ping`으로 확인함.

```bash
ping -c 1 8.8.8.8
```

### 탐지 로그 확인

```bash
sudo grep "CTINK_SNORT_DEPLOY_TEST" /var/log/snort/alert
```

정상 예시:

```
[1:1000101:1] CTINK_SNORT_DEPLOY_TEST
```

---

## Snort 삭제 테스트

### 룰 삭제

```bash
sudo python3 detection_rule_deployer.py remove --input snort_apply.json
```

정상 출력:

```json
{
  "status": "removed"
}
```

### 룰 파일에서 삭제 확인

```bash
sudo grep -n "CTINK_SNORT_DEPLOY_TEST" /opt/ctink/snort/ctink.rules
```

아무것도 안 나오면 삭제된 상태임.

### 삭제 후 탐지 안 되는지 확인

```bash
sudo truncate -s 0 /var/log/snort/alert
ping -c 1 8.8.8.8
sudo grep "CTINK_SNORT_DEPLOY_TEST" /var/log/snort/alert
```

아무것도 안 나오면 삭제 반영 완료임.

---

## YARA 적용 테스트

YARA는 네트워크 패킷이 아니라 파일을 탐지함.

기본 검사 대상 디렉토리:

```
/opt/ctink/yara/scan_target
```

### 적용 JSON 생성

```bash
cat > yara_apply.json << 'EOF'
{
  "rule_type": "yara",
  "file_location": "/opt/ctink/yara/rules/ctink_rules.yar",
  "rule_content": "rule CTINK_YARA_DEPLOY_TEST { strings: $a = \\"malware_test_string\\" condition: $a }"
}
EOF
```

### 룰 적용

```bash
sudo python3 detection_rule_deployer.py apply --input yara_apply.json
```

정상 출력:

```json
{
  "status": "success"
}
```

### 룰 파일 확인

```bash
sudo grep -n "CTINK_YARA_DEPLOY_TEST" /opt/ctink/yara/rules/ctink_rules.yar
```

출력되면 룰 파일에 추가된 상태임.

### YARA scanner 서비스 확인

```bash
sudo systemctl status ctink-yara-scanner.service --no-pager
```

`active`면 정상임.

### YARA 설정 파일 확인

```bash
sudo cat /etc/ctink/yara_rule_files.txt
sudo cat /etc/ctink/yara_rule_dirs.txt
sudo cat /etc/ctink/yara_target_dirs.txt
```

| 파일 | 역할 |
| --- | --- |
| `/etc/ctink/yara_rule_files.txt` | 스캔에 사용할 YARA 룰 파일 목록 |
| `/etc/ctink/yara_rule_dirs.txt` | YARA 룰 디렉토리 목록 |
| `/etc/ctink/yara_target_dirs.txt` | 검사 대상 디렉토리 목록 |

### 실제 공격 데이터 파일 생성

```bash
sudo mkdir -p /opt/ctink/yara/scan_target
echo "this file contains malware_test_string" | sudo tee /opt/ctink/yara/scan_target/malicious_sample.txt
```

### 탐지 로그 초기화

```bash
sudo mkdir -p /var/log/ctink
sudo touch /var/log/ctink/yara_scan.log
sudo truncate -s 0 /var/log/ctink/yara_scan.log
```

### scanner 재시작 후 대기

```bash
sudo systemctl restart ctink-yara-scanner.service
sleep 35
```

기본 스캔 주기는 30초임.

### 탐지 로그 확인

```bash
sudo grep "CTINK_YARA_DEPLOY_TEST" /var/log/ctink/yara_scan.log
```

정상 예시:

```
CTINK_YARA_DETECT CTINK_YARA_DEPLOY_TEST /opt/ctink/yara/scan_target/malicious_sample.txt
```

---

## YARA 삭제 테스트

### 룰 삭제

```bash
sudo python3 detection_rule_deployer.py remove --input yara_apply.json
```

정상 출력:

```json
{
  "status": "removed"
}
```

### 룰 파일에서 삭제 확인

```bash
sudo grep -n "CTINK_YARA_DEPLOY_TEST" /opt/ctink/yara/rules/ctink_rules.yar
```

아무것도 안 나오면 삭제된 상태임.

### 삭제 후 탐지 안 되는지 확인

기존 공격 테스트 파일은 그대로 둠.

```bash
sudo truncate -s 0 /var/log/ctink/yara_scan.log
sudo systemctl restart ctink-yara-scanner.service
sleep 35
sudo grep "CTINK_YARA_DEPLOY_TEST" /var/log/ctink/yara_scan.log
```

아무것도 안 나오면 삭제 반영 완료임.

---

## 전체 테스트 명령어

Snort 적용/삭제, YARA 적용/삭제를 한 번에 확인하는 명령어임.

```bash
cd ~/mycode/assign/CTI-nk/module

cat > snort_apply.json << 'EOF'
{
  "rule_type": "snort",
  "file_location": "/opt/ctink/snort/ctink.rules",
  "rule_content": "alert icmp any any -> any any (msg:\\"CTINK_SNORT_DEPLOY_TEST\\"; sid:1000101; rev:1;)"
}
EOF

cat > yara_apply.json << 'EOF'
{
  "rule_type": "yara",
  "file_location": "/opt/ctink/yara/rules/ctink_rules.yar",
  "rule_content": "rule CTINK_YARA_DEPLOY_TEST { strings: $a = \\"malware_test_string\\" condition: $a }"
}
EOF

sudo mkdir -p /var/log/snort /var/log/ctink /opt/ctink/yara/scan_target
sudo touch /var/log/snort/alert /var/log/ctink/yara_scan.log

echo "[1] Snort apply"
sudo python3 detection_rule_deployer.py apply --input snort_apply.json
sudo grep -n "CTINK_SNORT_DEPLOY_TEST" /opt/ctink/snort/ctink.rules
sudo truncate -s 0 /var/log/snort/alert
ping -c 1 8.8.8.8
sudo grep "CTINK_SNORT_DEPLOY_TEST" /var/log/snort/alert

echo "[2] Snort remove"
sudo python3 detection_rule_deployer.py remove --input snort_apply.json
sudo grep -n "CTINK_SNORT_DEPLOY_TEST" /opt/ctink/snort/ctink.rules
sudo truncate -s 0 /var/log/snort/alert
ping -c 1 8.8.8.8
sudo grep "CTINK_SNORT_DEPLOY_TEST" /var/log/snort/alert

echo "[3] YARA apply"
echo "this file contains malware_test_string" | sudo tee /opt/ctink/yara/scan_target/malicious_sample.txt
sudo python3 detection_rule_deployer.py apply --input yara_apply.json
sudo grep -n "CTINK_YARA_DEPLOY_TEST" /opt/ctink/yara/rules/ctink_rules.yar
sudo truncate -s 0 /var/log/ctink/yara_scan.log
sudo systemctl restart ctink-yara-scanner.service
sleep 35
sudo grep "CTINK_YARA_DEPLOY_TEST" /var/log/ctink/yara_scan.log

echo "[4] YARA remove"
sudo python3 detection_rule_deployer.py remove --input yara_apply.json
sudo grep -n "CTINK_YARA_DEPLOY_TEST" /opt/ctink/yara/rules/ctink_rules.yar
sudo truncate -s 0 /var/log/ctink/yara_scan.log
sudo systemctl restart ctink-yara-scanner.service
sleep 35
sudo grep "CTINK_YARA_DEPLOY_TEST" /var/log/ctink/yara_scan.log
```

삭제 테스트에서 마지막 `grep`은 아무것도 출력되지 않아야 정상임.

---

## 환경변수 설명

환경변수는 실행 환경마다 경로나 서비스 이름을 바꾸고 싶을 때 사용함.

설정하지 않으면 기본값을 사용함.

### Snort 환경변수

| 환경변수 | 기본값 | 설명 |
| --- | --- | --- |
| `SNORT_CONF` | `/etc/snort/snort.conf` | Snort 메인 설정 파일 |
| `SNORT_DEFAULT_FILE` | `/etc/default/snort` | Ubuntu Snort 실행 옵션 파일 |
| `SNORT_LOG_DIR` | `/var/log/snort` | Snort 로그 디렉토리 |
| `SNORT_SERVICE_NAME` | `snort` | Snort systemd 서비스 이름 |
| `SNORT_DEFAULT_RULE_FILE` | `/etc/snort/rules/local.rules` | `file_location` 생략 시 사용할 Snort 기본 룰 파일 |

### YARA 환경변수

| 환경변수 | 기본값 | 설명 |
| --- | --- | --- |
| `YARA_DEFAULT_RULE_FILE` | `/opt/ctink/yara/rules/ctink_rules.yar` | `file_location` 생략 시 사용할 YARA 기본 룰 파일 |
| `YARA_RULE_FILES_FILE` | `/etc/ctink/yara_rule_files.txt` | 스캐너가 읽을 YARA 룰 파일 목록 |
| `YARA_RULE_DIRS_FILE` | `/etc/ctink/yara_rule_dirs.txt` | 스캐너가 읽을 YARA 룰 디렉토리 목록 |
| `YARA_TARGET_DIRS_FILE` | `/etc/ctink/yara_target_dirs.txt` | 스캐너가 검사할 대상 디렉토리 목록 |
| `YARA_DEFAULT_SCAN_TARGETS` | `/opt/ctink/yara/scan_target` | 기본 검사 대상 디렉토리 |
| `YARA_SCANNER_SCRIPT` | `/usr/local/bin/ctink_yara_scanner.py` | 자동 생성되는 YARA 스캐너 스크립트 |
| `YARA_SCANNER_SERVICE` | `ctink-yara-scanner.service` | YARA scanner systemd 서비스 이름 |
| `YARA_SCAN_INTERVAL_SEC` | `30` | YARA 스캔 주기, 초 단위 |
| `YARA_LOG_FILE` | `/var/log/ctink/yara_scan.log` | YARA 탐지 로그 파일 |

### 공통 환경변수

| 환경변수 | 기본값 | 설명 |
| --- | --- | --- |
| `CTINK_DEPLOY_RELOAD` | `true` | `true`면 적용/삭제 후 서비스 실행 또는 재시작함 |
| `RABBITMQ_URL` | `amqp://guest:guest@localhost:5672/%2F` | RabbitMQ 접속 주소 |
| `RULE_DEPLOY_APPLY_QUEUE` | `rule_deploy_apply` | 정책 적용 요청 MQ queue |
| `RULE_DEPLOY_REMOVE_QUEUE` | `rule_deploy_remove` | 정책 삭제 요청 MQ queue |
| `DEPLOY_COMMAND_TIMEOUT` | `30` | 외부 명령어 실행 제한 시간, 초 단위 |

---

## 환경변수 설정 예시

한 번만 적용:

```bash
sudo YARA_SCAN_INTERVAL_SEC=10 python3 detection_rule_deployer.py apply --input yara_apply.json
```

위 명령은 YARA 스캔 주기를 10초로 실행함.

---

## 자주 발생하는 문제

### sudo 없이 실행함

증상:

```json
{
  "status": "failed to apply",
  "message": "root privileges required..."
}
```

해결:

```bash
sudo python3 detection_rule_deployer.py apply --input apply.json
```

### Snort 탐지 로그가 안 나옴

확인:

```bash
sudo systemctl status snort --no-pager
sudo grep -n "output alert_fast" /etc/snort/snort.conf
sudo grep -n "^ALERTMODE" /etc/default/snort
sudo tail -n 30 /var/log/snort/alert
```

재시작:

```bash
sudo systemctl restart snort
```

### YARA 탐지 로그가 안 나옴

확인:

```bash
sudo systemctl status ctink-yara-scanner.service --no-pager
sudo cat /etc/ctink/yara_rule_files.txt
sudo cat /etc/ctink/yara_target_dirs.txt
sudo tail -n 50 /var/log/ctink/yara_scan.log
```

재시작:

```bash
sudo systemctl restart ctink-yara-scanner.service
sleep 35
sudo tail -n 50 /var/log/ctink/yara_scan.log
```

### YARA 검사 대상 디렉토리를 추가하고 싶음

예시로 `/home/user/downloads`를 검사 대상에 추가함.

```bash
echo "/home/user/downloads" | sudo tee -a /etc/ctink/yara_target_dirs.txt
sudo systemctl restart ctink-yara-scanner.service
```

---

## 대량 룰 배포 시 권장 방식

룰이 많을수록 `file_location`을 계속 바꾸지 않는 게 좋음.

고정된 룰 파일 하나에 계속 추가하는 방식이 운영하기 쉬움.

권장 경로:

| 종류 | 권장 file_location |
| --- | --- |
| Snort | `/opt/ctink/snort/ctink.rules` |
| YARA | `/opt/ctink/yara/rules/ctink_rules.yar` |

이렇게 하면 불필요한 룰 파일이 여러 개 생기지 않음.

---

## 추가 백업 관련 사항

해당 모듈은 “/tmp/ctink_rule_backups” 경로에 `/etc/snort/snort.conf`, `/etc/default/snort`, `/etc/snort/rules/local.rules`, `/opt/ctink/yara/rules/ctink_rules.yar` 에 수정 사항이 생길 때 백업해서 저장한다. 따라서 백업 파일이 쌓일 수 있으므로, 오래된 백업 내용은 다음의 설정을 통해 주기적으로 삭제하길 권장한다.

```python
sudo crontab -e
```

아래 줄 추가:

```python
0 3 * * * find /tmp/ctink_rule_backups -type f -name "*.bak" -mtime +2 -delete
```

→ 매일 새벽 3시에 2일 지난 `.bak` 파일을 삭제한다.

---

## 요약

Snort:

```
apply → 룰 파일 추가 → snort.conf include → Snort restart → /var/log/snort/alert 탐지 로그
remove → 룰 파일에서 제거 → Snort restart → 해당 룰 탐지 중지
```

YARA:

```
apply → 룰 파일 추가 → scanner service 실행 → /var/log/ctink/yara_scan.log 탐지 로그
remove → 룰 파일에서 제거 → scanner service 유지 → 해당 룰 탐지 중지
```
