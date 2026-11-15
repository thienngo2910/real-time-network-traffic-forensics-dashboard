# Đề tài cuối kỳ: Real-Time Network Traffic Forensics Dashboard

## Mục tiêu

Xây dựng dashboard cục bộ để quan sát lưu lượng mạng IPv4 gần thời gian thực, hỗ trợ triage từ PCAP hoặc capture trực tiếp, và lưu lại thông tin gắn với frame để kiểm tra thủ công. Hệ thống bổ sung góc nhìn tổng quan được cấu hình theo bộ quy tắc của đề tài. Không tuyên bố thay thế Wireshark hoặc ưu việt tổng quát.

## Kiến trúc

1. Nguồn dữ liệu: classic PCAP replay hoặc Scapy live capture.
2. Bộ giải mã: Ethernet/VLAN đơn, raw IPv4, Linux cooked v1; IPv4 TCP/UDP/ICMP.
3. State engine: bộ đếm protocol/host, timeline rolling, event buffer, heuristic alerts và metadata ICFR cơ bản.
4. Web server cục bộ: Python standard library HTTP server, JSON state endpoint và export JSON.
5. Frontend: HTML/CSS/JavaScript không cần framework hoặc dịch vụ ngoài.

## Hiển thị và phát hiện

Dashboard có KPI packets/bytes/protocols/findings; timeline 30 giây; protocol mix; top talkers; bảng evidence có frame, timestamp capture, source/destination, port, giao thức, độ dài và payload preview dạng hex; findings có frame nguồn. Heuristic ban đầu: ICMP rate từ 30 gói/5 giây; TCP SYN tới ít nhất 20 cổng đích khác nhau/10 giây; ICFR duplicate; ICFR chunk conflict.

Ngưỡng heuristic chưa được hiệu chuẩn từ traffic thật. Alert chỉ là dấu hiệu cần điều tra, không xác nhận tấn công. Payload preview giới hạn 24 byte và hiển thị hex; nội dung ứng dụng không được giải mã.

## Chạy demo

Chế độ replay dùng fixture offline:

    python -m icfr.dashboard --pcap datasets/generated/combined.pcap --speed 1

Chế độ live trên Ubuntu cần quyền packet capture và interface do người vận hành xác minh:

    sudo .venv/bin/python -m icfr.dashboard --live --interface <interface> --filter "ip"

Mặc định dịch vụ chỉ lắng nghe loopback. Để Windows truy cập dashboard trên Ubuntu, cần bind đúng địa chỉ interface trong mạng lab và cấu hình firewall. Chưa thực hiện capture live trên VM trong quá trình xây dựng.

## Đánh giá đề xuất

Đánh giá nên phát cùng PCAP qua dashboard và Wireshark/TShark, so sánh thời gian tìm frame, độ chính xác đếm protocol/talkers, số alert đúng/sai khi có ground truth, và độ trễ cập nhật. Dataset hiện có chủ yếu chứa ICMP/ICFR; cần bổ sung PCAP TCP/UDP có nhãn trước khi báo cáo hiệu quả trên traffic tổng quát. Chưa có phép đo so sánh với Wireshark trong phiên bản này.

## Giới hạn

Chỉ IPv4 và classic PCAP; chưa hỗ trợ PCAPNG, IPv6, IPv4 fragment reassembly, TCP stream reassembly, DNS/TLS semantics, authentication hoặc multi-user access. Buffer packet bị giới hạn nhưng counters/session state giữ trong RAM đến khi tiến trình dừng. Capture thật chưa được thực hiện. Đây là nguyên mẫu học thuật, không phải NIDS/SIEM production.
