# Báo cáo phương pháp

## Tóm tắt

Đồ án xây dựng nguyên mẫu phân tích PCAP để tái dựng dữ liệu thử nghiệm được mang trong ICMP. Metadata ICFR cung cấp định danh truyền, chỉ số chunk và tổng chunk. Analyzer dùng các trường đó để sắp xếp dữ liệu và báo cáo các điều kiện khiến kết quả chưa thể được xem là đầy đủ. Đánh giá chạy trên PCAP tổng hợp có ground truth đã biết.

## Câu hỏi nghiên cứu

Trong capture ICFR có nhiễu ping, đảo thứ tự, duplicate, mất chunk và payload xung đột, phương pháp dùng metadata biểu hiện thế nào so với cách ghép tuần tự theo thứ tự frame?

## Phương pháp

Sender chia byte nguồn thành chunk kích thước cấu hình, mặc định 512 byte. Mỗi payload mở đầu bằng header 16 byte: magic ICFR, File ID, index bắt đầu từ 0 và tổng chunk; các số là unsigned 32-bit big-endian. Gói ICMP mang header và dữ liệu.

Analyzer đọc classic PCAP, trích IPv4 và ICMP Echo, xác nhận magic/độ dài/giới hạn metadata, rồi phân nhóm theo địa chỉ nguồn, đích, File ID và tổng chunk. Mỗi index lưu số frame quan sát. Bản sao cùng nội dung được đánh dấu duplicate nhưng chỉ dùng một bản; cùng index với dữ liệu khác nhau là conflict và bị loại khỏi byte dựng. Index vắng mặt được liệt kê. Chỉ nhóm đủ index, không conflict, mới complete. SHA-256 được tính trên byte dựng và đối chiếu hash ground truth độc lập.

Baseline ghép tuần tự tất cả body ICFR theo thứ tự capture. Đây là đối chứng tối giản, không đại diện cho mọi công cụ hiện đại.

## Dữ liệu và tính lặp lại

Script tạo payload nhị phân xác định, chia chunk 128 byte. Bảy PCAP gồm complete, noise, reordered, duplicate, missing, conflict và combined. Generator ghi Ethernet/IPv4/ICMP và classic PCAP bằng thư viện chuẩn Python. scripts/evaluate.py tái tạo fixture, chạy analyzer, so hash và sinh CSV/JSON.

## Kết quả

Kết quả cụ thể nằm trong results/evaluation.csv và results/evaluation.json; SHA-256 nguồn độc lập nằm trong datasets/generated/ground_truth.json. Các số được sinh từ lần chạy đánh giá của project, không phải số liệu giả định. Hoàn chỉnh theo metadata và hash khớp ground truth là hai tiêu chí riêng. Trong fixture mất/xung đột, analyzer báo không hoàn chỉnh; baseline không khôi phục đúng khi frame bị xáo trộn hoặc lặp.

## Diễn giải

Chunk index khắc phục phụ thuộc thứ tự frame với ICFR nhận diện được. Metadata total cho phép phát hiện khoảng trống. So sánh nội dung theo index phân biệt bản sao nguyên vẹn với xung đột. Kiểm tra giúp tránh tuyên bố khôi phục đầy đủ khi chứng cứ thiếu/mâu thuẫn. Hash khớp fixture chỉ xác nhận byte dựng giống byte nguồn fixture đó; không xác thực người gửi hoặc capture thực tế.

## Giới hạn và đe dọa tới tính hợp lệ

Đây là mô hình tự tạo, ít kịch bản và không phải dữ liệu mạng thật. Baseline đơn giản. Parser bỏ qua IPv4 fragmentation và chưa hỗ trợ IPv6, PCAPNG hay link type khác. Không có xác thực metadata; kẻ tạo gói có thể giả File ID/index. Xung đột được báo nhưng không có chứng cứ ngoài để quyết định bản đúng. Tái sử dụng cùng khóa trong cùng cặp IP có thể nhập nhằng. Không đánh giá tốc độ, mở rộng quy mô hay tỷ lệ lỗi thống kê. Do đó không tuyên bố tính mới hoặc khả năng tổng quát.

## Hướng demo và công việc tiếp theo

Demo nên dùng hai VM trong mạng NAT cô lập, file mẫu vô hại, capture tcpdump và kiểm tra hash hai đầu. Xác minh IP/interface vì các IP đã nhắc trước là lịch sử. Tiếp theo có thể thêm PCAPNG/IPv6, checksum chunk, schema version, multi-transfer collision, capture corruption và nhiều seed; cần đo trước khi báo cáo.
