# ReflectiveDLL
Repository này tạo một thư viện động(DLL) Reflective và loader cho nó.
# Tạo Reflective Dynamic link library
Tiến hành tạo một Reflective DLL. Trong DLL này, một hàm DllMain được thiết lập để xử lý các tác vụ chính của thư viện. Ở đây, để cho đơn giản DLL sẽ chỉ hiển thị một MessageBox đơn giản báo hiệu tiến trình nạn nhân đã bị chèn mã.
```C
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "Process nay da bi inject!", "Injected Notice", MB_OK);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```
## ReflectiveLoader
Đây là một hàm đặc thù với cơ chế tự tải chính phản thân nó thay vì sử dụng các API của Windows như LoadLibrary từ kernel32. Làm như vậy để DLL sẽ không cần phải có mặt trên đĩa, do LoadLibrary nhân tham số là
đường dẫn tới DLL trên đĩa. Đồng thời cơ chế tự tải này giúp DLL không có mặt trong danh sách module được tải bời tiến trình, nên sẽ càng khó để phát hiện hơn cách tải sử dụng LoadLibrary thông thường.
```C
extern "C" __declspec(dllexport) void ReflectiveLoader()
```
Trong đó, khai báo extern "C" để complier biết và sử dụng cách đặt tên kiểu 'C' cho hàm, giúp tên của hàm không bị biến đổi "name mangling" (sự biến đổi nhằm hỗ trợ tính đa hình), vẫn giữ được tên gốc.
Cách làm này giúp hàm có thể được gọi dễ dàng để liên kết với module khác, bất kể chương trình viết bằng ngôn ngữ gì.

__declspec(dllexport) là directive để khai báo hàm được xuất ra từ DLL.

Trong ReflectiveLoader(), sẽ lần lượt thiết lập các cơ chế tự tìm và tải bản thân trong bộ nhớ tiến trình nạn nhân.
### Quá trình tự xác định vị trí.
```C
HMODULE hModule = NULL;
__asm
{
    call getip
getip:
    pop eax
    sub eax, 5
    mov hModule, eax
}
```
Đoạn code sau thực hiện lệnh call, sẽ đồng thời nhảy đến nhãn 'getip' và push địa chỉ trả về lên stack. Khi đó, lệnh pop sẽ lưu địa chỉ trả về trong eax, và trừ đi 5 đơn vị (do lệnh call trong x86 dài 5 đơn vị) nên sẽ trả về địa chỉ của lệnh call. -> Ta có được một địa chỉ tham chiếu hModule nằm bên trong hàm ReflectiveLoader. Từ địa chỉ tham chiếu này, ta sẽ dò ngược lên để tìm chữ ký "MZ".
```C
ULONG_PTR uLibAddress = (ULONG_PTR)hModule;
ULONG_PTR uHeader;
while (TRUE) {
    if (((PIMAGE_DOS_HEADER)uLibAddress)->e_magic == IMAGE_DOS_SIGNATURE) {
        uHeader = ((PIMAGE_DOS_HEADER)uLibAddress)->e_lfanew;
        // Trong x64, mot so instruct co gia tri giong 'MZ', vd: POP r10
        // Vay nen can check gia tri e_lfanew nam trong [64,1024] cho an toan!
        if (uHeader >= sizeof(IMAGE_DOS_HEADER) && uHeader < 1024) {
            uHeader += uLibAddress;
            // break neu tim thay MZ + PE header
            if (((PIMAGE_NT_HEADERS)uHeader)->Signature == IMAGE_NT_SIGNATURE)
                break;
        }
    }
    uLibAddress--;
}
```
Đoạn code này trước hết gán giá trị uLibAddress thành PIMAGE_DOS_HEADER và kiểm tra "MZ", nếu không phải thì tiếp tục giảm giá trị 1 byte để đi ngược về. Tuy nhiên trong x64 thì có những instruction như 'POP r10' có cùng giá trị với "MZ" dẫn tới false positive, nên cần check kích thước e_lfanew thuộc khoảng cho phép và NT signature hợp lệ.
### Quá trình lấy địa chỉ các hàm cần thiết
Trong quá trình thực hiện ReflectiveLoader, không thể tin tưởng vào cơ chế tự động của linker để thực hiện gọi các hàm API cần cho việc ánh xạ image DLL, như GetProcAddress hay VirtualAlloc. Nguyên nhân do DLL được tải từ bộ nhớ chứ không thông qua trình tải chuẩn của Windows - dẫn tới bảng nhập IAT của module có thể không được thiết lập chuẩn, cần xử lý thủ công để lấy địa chỉ các API.
1. Tìm Base Address của kernel32.dll
Cần truy xuất Process Environment Block (PEB) của tiến trình. Mỗi tiến trình trong Windows có một cấu trúc PEB chứa thông tin về module đã nạp. 'kernel32.dll' luôn là một trong những module nạp đầu tiên, nên ReflectiveLoader có thể duyệt danh sách này để tìm địa chỉ của nó.
Dùng PEB->Ldr->InMemoryOrderModuleList để tìm kernel32.dll và lấy địa chỉ.
