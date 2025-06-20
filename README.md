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
Đây là một hàm đặc thù với cơ chế tự tải chính bản thân nó thay vì sử dụng các API của Windows như LoadLibrary từ kernel32. Làm như vậy để DLL sẽ không cần phải có mặt trên đĩa, do LoadLibrary nhận tham số là
đường dẫn tới DLL trên đĩa. Đồng thời cơ chế tự tải này giúp DLL không có mặt trong danh sách module được tải bời tiến trình, nên sẽ càng khó để phát hiện hơn cách tải sử dụng LoadLibrary thông thường.
```C
extern "C" __declspec(dllexport) void ReflectiveLoader()
```
Trong đó, khai báo extern "C" để complier biết và sử dụng cách đặt tên kiểu 'C' cho hàm, giúp tên của hàm không bị biến đổi "name mangling" (sự biến đổi nhằm hỗ trợ tính đa hình), vẫn giữ được tên gốc.
Cách làm này giúp hàm có thể được gọi dễ dàng để liên kết với module khác, bất kể chương trình viết bằng ngôn ngữ gì.

__declspec(dllexport) là directive để khai báo hàm được xuất ra từ DLL.

Trong ReflectiveLoader(), sẽ lần lượt thiết lập các cơ chế tự tìm và tải bản thân trong bộ nhớ tiến trình nạn nhân.
### Quá trình tự xác định vị trí.
Có thể dùng 'caller' như Stephen Fewer để DLL tự chủ động hơn thay vì phụ thuộc vào injector. Ở đây tôi sẽ dùng Injector để truyền địa chỉ DLL được chèn trong bộ nhớ thay vì để DLL tự tải. 
### Quá trình lấy địa chỉ các hàm cần thiết
Trong quá trình thực hiện ReflectiveLoader, không thể tin tưởng vào cơ chế tự động của linker để thực hiện gọi các hàm API cần cho việc ánh xạ image DLL, như GetProcAddress hay VirtualAlloc. Nguyên nhân do DLL được tải từ bộ nhớ chứ không thông qua trình tải chuẩn của Windows - dẫn tới bảng nhập IAT của module có thể không được thiết lập chuẩn, cần xử lý thủ công để lấy địa chỉ các API.
1. Tìm Base Address của kernel32.dll
Cần truy xuất Process Environment Block (PEB) của tiến trình. Mỗi tiến trình trong Windows có một cấu trúc PEB chứa thông tin về module đã nạp. 'kernel32.dll' luôn là một trong những module nạp đầu tiên, nên ReflectiveLoader có thể duyệt danh sách này để tìm địa chỉ của nó.
```C
typedef struct _PEB_LDR_DATA //, 7 elements, 0x28 bytes
{
	DWORD dwLength;
	DWORD dwInitialized;
	LPVOID lpSsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;
```
Dùng PEB->Ldr->InMemoryOrderModuleList để tìm kernel32.dll và lấy địa chỉ.
InMemoryOrderModuleList là một con trỏ trỏ tới điểm bắt đầu của link list - danh sách liên kết - các con trỏ đi tới mô tả các module được nạp vào chương trình (LDR_DATA_TABLE_ENTRY).
```C
typedef struct _LDR_DATA_TABLE_ENTRY
{
	//LIST_ENTRY InLoadOrderLinks; // As we search from PPEB_LDR_DATA->InMemoryOrderModuleList we dont use the first entry.
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STR FullDllName;
	UNICODE_STR BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY HashTableEntry;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
```
Với cấu trúc này, kiểm tra xem BaseDllName.Buffer có phải tên thư viện cần tìm, và nếu đúng thì lấy module base = DllBase. Như vậy đã lấy được địa chỉ vùng nhớ cấp phát cho dll đó nằm trong chương trình. Duyệt qua vùng bộ nhớ PE này và đọc Export directory:
```C
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;     // RVA from base of image
    DWORD AddressOfNames;         // RVA from base of image
    DWORD AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY;
```
* exportDir = module base + export RVA. exportDir sẽ trỏ tới vùng nhớ chứa struct IMAGE_EXPORT_DIRECTORY như trình bày ở trên. Cấu trúc này mô tả các hàm xuất của module, cho biết thông tin về các hàm.
* Duyệt qua các tên hàm được trỏ trong list địa chỉ AddressOfNames, lấy giá trị ordinal và thu về địa chỉ tương ứng ordinal đó.
* Trong mục này, ta tìm và lấy 2 thư viện "kernel32.dll" (cho các hàm GetProcAddress, VirtualAlloc, LoadLibraryA) và "ntdll.dll" (cho hàm NtFlushInstructionCache).
