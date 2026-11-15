# ICFR Network Forensics

**Đề tài:** Nghiên cứu và đánh giá phương pháp tái dựng dữ liệu truyền qua giao thức ICMP từ bằng chứng PCAP trong môi trường mạng có nhiễu và mất gói.

Project Python minh họa giao thức thử nghiệm ICFR (ICMP File Reconstruction). Các capture trong datasets/generated/ là PCAP tổng hợp tái lập được, không phải bằng chứng từ mạng thật. Chỉ dùng sender trong mạng lab bạn được phép kiểm soát.

## Kết quả đồ án

- Scapy sender chia file thành chunk, đóng metadata vào ICMP Echo Request.
- Bộ đọc PCAP IPv4/ICMP nhận dạng ICFR, nhóm theo nguồn/đích/File ID/Total.
- Analyzer sắp xếp bằng chunk index, bỏ qua ping thường, nhận diện duplicate giống hệt nhau, phát hiện xung đột, báo chunk thiếu, dựng dữ liệu có sẵn và ghi số frame bằng chứng.
- Đối chứng baseline ghép payload theo capture order.
- Dataset có đủ, nhiễu, đảo thứ tự, trùng lặp, mất chunk, xung đột và tình huống kết hợp.
- SHA-256 ground truth độc lập và kết quả đánh giá được sinh bởi script.

## Yêu cầu và chạy trên Ubuntu Server

    sudo apt update
    sudo apt install -y python3 python3-venv python3-pip
    cd ~/icmp-lab
    python3 -m venv .venv
    source .venv/bin/activate
    python -m pip install -e .
    python scripts/evaluate.py

Dataset và parser dùng thư viện chuẩn Python; Scapy chỉ cần cho việc gửi thật:

    python -m pip install scapy
    sudo .venv/bin/python -m icfr.sender samples/input.bin --destination 192.168.201.1 --chunk-size 512

Gửi gói cần quyền raw socket; chạy trong lab riêng. Không bật gửi trực tiếp nếu chưa xác nhận đúng interface/mạng đích. --count-only in metadata/hash mà không gửi.

    python -m icfr.cli dataset datasets/generated
    python -m icfr.cli analyze capture.pcap -o results/capture

## Real-Time Network Traffic Forensics Dashboard

Khởi chạy dashboard cục bộ. Mặc định chỉ bind vào loopback 127.0.0.1.

Phát lại capture mẫu:

    python -m icfr.dashboard --pcap datasets/generated/combined.pcap --speed 1

Mở http://127.0.0.1:8765. `--speed 0` phát lại nhanh nhất; `--speed 1` theo timestamp capture.

Bắt trực tiếp trên Ubuntu (cần quyền packet capture; xác minh interface trước bằng `ip -br addr`):

    sudo .venv/bin/python -m icfr.dashboard --live --interface enp0s3 --filter "ip"

Nếu truy cập dashboard Ubuntu từ Windows, bind đúng địa chỉ Ubuntu trong mạng NAT tin cậy và giới hạn firewall. Không bind `0.0.0.0` trên mạng công cộng; ứng dụng chưa có đăng nhập/mã hóa.

Dashboard hiển thị packet count/bytes, protocol mix, biểu đồ 30 giây, top talkers, bảng packet có frame/time/endpoint/ports/ICMP type và payload preview dạng hex; session xuất được JSON. Parser hỗ trợ IPv4 TCP/UDP/ICMP trên classic PCAP (Ethernet, VLAN đơn, raw IPv4, Linux cooked v1). Bắt trực tiếp cần Scapy và libpcap/Npcap phù hợp.

### Cảnh báo heuristic

- Ít nhất 30 gói ICMP từ một nguồn trong cửa sổ 5 giây.
- SYN đến ít nhất 20 cổng đích khác nhau từ một nguồn trong 10 giây.
- ICFR duplicate hoặc cùng index có payload khác nhau.

Ngưỡng chỉ phục vụ triage demo, có thể gây false positive/negative và không phải kết luận xâm nhập. Dashboard không dựng file ICFR trực tiếp và chưa phân tích TCP stream, DNS semantics, TLS hay IPv6. Timestamp PCAP gốc và frame được giữ trong bảng; biểu đồ dùng thời điểm dashboard nhận gói để hiển thị cả replay capture cũ.

## Định dạng ICFR v1

| Offset | Kích thước | Trường |
|---:|---:|---|
| 0 | 4 | ASCII ICFR |
| 4 | 4 | File ID, unsigned big-endian |
| 8 | 4 | Chunk index, zero-based, unsigned big-endian |
| 12 | 4 | Tổng số chunk, unsigned big-endian |
| 16 | còn lại | Dữ liệu chunk |

Analyzer nhóm theo IPv4 nguồn, đích, File ID và tổng chunk. Kích thước chunk sender mặc định 512 byte, tùy chỉnh được. Big-endian là quy ước định dạng riêng, không phải yêu cầu bắt buộc của ICMP.

## Đầu ra và diễn giải

- results/evaluation.csv, results/evaluation.json: so sánh baseline/analyzer.
- results/<scenario>/report.json: hash tính được, trạng thái hoàn chỉnh, chunk thiếu/trùng/xung đột và mapping index → frame.
- results/<scenario>/recovered_*.bin: byte tái dựng. Với xung đột, index xung đột bị loại khỏi dữ liệu dựng.

Hash được báo cáo là hash của dữ liệu dựng. Chỉ gọi là khớp khi so với hash nguồn biết độc lập (như ground truth); PCAP đơn lẻ không tự chứng minh hash ban đầu.

## Phương pháp và đánh giá

results/evaluation.csv là kết quả chạy trên 7 PCAP tổng hợp cố định. Baseline ghép các body ICFR theo thứ tự frame, không loại duplicate hay phát hiện mất/xung đột. Analyzer dùng metadata để tái sắp xếp và biểu diễn giới hạn chứng cứ. Tiêu chí gồm hoàn chỉnh, SHA-256 so nguồn gốc, số index thiếu/trùng/xung đột. Kết quả chỉ mô tả các fixture cụ thể, không phải ước lượng tổng quát hoặc tuyên bố tính mới.

Dataset chưa mô phỏng checksum lỗi, phân mảnh IPv4, capture cắt cụt, IPv6, mã hóa, multi-file collision cùng khóa, retransmission timing hay nhiễu có chủ đích.

## Hướng demo VMware NAT

1. Xác nhận Ubuntu VM hiện được cấp IP/interface và Windows VM đang ở cùng mạng NAT. Địa chỉ 192.168.201.130 và 192.168.201.1 chỉ là giá trị lịch sử, cần xác minh lại tại buổi demo.
2. Trên Ubuntu, tạo file thử nghiệm trong ~/icmp-lab/samples/ (giữ dữ liệu cũ), chạy tcpdump -ni <interface> -w ~/icmp-lab/demo.pcap icmp trong một terminal.
3. Ở terminal khác chạy sender với địa chỉ Windows NAT đã kiểm tra. Dừng tcpdump bằng Ctrl+C.
4. Chép PCAP vào project, chạy analyzer và đối chiếu hash file gốc với hash dựng.
5. Có thể mở capture trong Wireshark/TShark để trình bày frame và payload.

Không có kết nối trực tiếp tới Ubuntu/VMware được thực hiện trong quá trình xây dựng này. Không có dữ liệu lab cũ bị đọc/ghi hoặc thay đổi. Demo mạng thật chưa được xác nhận.

## Giới hạn

Analyzer hỗ trợ classic PCAP với Ethernet, raw IPv4 hoặc Linux cooked v1; chỉ đọc IPv4 ICMP Echo không phân mảnh. ICFR không có authentication, encryption, checksum/hash theo chunk, version negotiation hoặc sửa lỗi. Metadata tự khai báo không chứng minh nguồn gốc/tính xác thực. Capture có thể đã mất gói trước khi lưu. Kết quả synthetic không phản ánh điều kiện mạng thực.

## Cấu trúc

    src/icfr/          parser, analyzer, CLI, generator, Scapy sender
    datasets/generated/ synthetic PCAP and ground truth
    scripts/evaluate.py
    results/           generated reports and reconstructed files

