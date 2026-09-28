from cypher.parsers.auth import parse_auth_line
from cypher.parsers.apache import parse_apache_line

def test_auth_parse():
    ln = "Jan  1 12:34:56 host sshd[1234]: Failed password for invalid user admin from 1.2.3.4 port 5555 ssh2"
    rec = parse_auth_line(ln)
    assert rec and rec["is_failed_ssh"] == 1 and rec["is_invalid_user"] == 1

def test_apache_parse():
    ln = '127.0.0.1 - - [10/Oct/2025:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"'
    rec = parse_apache_line(ln)
    assert rec and rec["status"] == 200 and rec["method"] == "GET"
