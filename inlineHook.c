/*
thumb16 thumb32 arm32 inlineHook
author: ele7enxxh
mail: ele7enxxh@qq.com
website: ele7enxxh.com
modified time: 2015-01-23
created time: 2015-11-30
*/

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <dirent.h>
#include <signal.h>
#include <sys/mman.h>
// #include <asm/ptrace.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include "relocate.h"
#include "include/inlineHook.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

// 이거 뭐지.. 음수 치환 & addr?
// https://stackoverflow.com/questions/3023909/what-is-the-trick-in-paddress-page-size-1-to-get-the-pages-base-address
// 페이지 base를 얻는 거라는데? 근데 왜 이걸 얻지??
// https://www.lazenca.net/display/TEC/03.ROP%28Return+Oriented+Programming%29+-+mmap%2C+mprotect
// mprotect 때문인데 이유가 나오네.. ( man page에도 나옴.)
#define PAGE_START(addr)	(~(PAGE_SIZE - 1) & (addr))
// 아래는 머지? thumb 인가?
#define SET_BIT0(addr)		(addr | 1)
#define CLEAR_BIT0(addr)	(addr & 0xFFFFFFFE)
#define TEST_BIT0(addr)		(addr & 1)
// 이거 thread 제어 용 define
#define ACTION_ENABLE	0
#define ACTION_DISABLE	1
	
enum hook_status {
	REGISTERED,
	HOOKED,
};
// registration 했을때 저장되는 정보 인가?
struct inlineHookItem {
	uint32_t target_addr; // 타겟 함수 주소. 
	uint32_t new_addr; 
	uint32_t **proto_addr; // tranpolin?
	void *orig_instructions; // malloc으로 공간 만들고, target addr의 prolgue 저장 ( 근데 arm은 inst 3개 thumb은 4개?? )
	int orig_boundaries[4];
	
	int trampoline_boundaries[20];
	int count;
	void *trampoline_instructions;
	int length; // orig_instructions 갯수.. 12나 8 byte이다 .
	int status;  // 등록 상태인지, Hooked인지 hook_status enum 값을 저장.
	int mode;
};

struct inlineHookInfo {
	struct inlineHookItem item[1024]; // 등록을 1024개 가능하게 해준듯. 
	int size;
};

static struct inlineHookInfo info = {0}; // 이렇게 초기화 가능한가 보네.. 아.. 배열.. 이지. 


/*
* freeze에서 씀
* exclude_tid : 현재 tid
* tids : 나머지 tid 저장하는 위치
*/
static int getAllTids(pid_t exclude_tid, pid_t *tids)
{
	char dir_path[32];
	DIR *dir;
	int i;
	struct dirent *entry;
	pid_t tid;

	if (exclude_tid < 0) {
		snprintf(dir_path, sizeof(dir_path), "/proc/self/task");
	}
	else {
		snprintf(dir_path, sizeof(dir_path), "/proc/%d/task", exclude_tid);
	}

	dir = opendir(dir_path);
    if (dir == NULL) {
    	return 0;
    }

    i = 0;
    while((entry = readdir(dir)) != NULL) {
    	tid = atoi(entry->d_name);
    	if (tid != 0 && tid != exclude_tid) {
    		tids[i++] = tid;
    	}
    }
    closedir(dir);
    return i;
}

/*
*  현재 PC 위치에 따른 처리 .
*/
static bool doProcessThreadPC(struct inlineHookItem *item, struct pt_regs *regs, int action)
{
	int offset;
	int i;

	switch (action)
	{
		case ACTION_ENABLE:  // hook일때
			offset = regs->ARM_pc - CLEAR_BIT0(item->target_addr); // 현재 pc의 위치에관해  target_addr에서 상대 위치 찾은듯.
				// offset이 음수이면? => 아직 수정 위치에 오지 못했다는 것. 
				// offset이 0과 양수면 => 수정 위치를 넘었다는 것. 
			for (i = 0; i < item->count; ++i) { // count 는 boundary 카운트.. origin에서 옯겨온 프롤로그 offset들. => 0 이 target_addr 위치 
				if (offset == item->orig_boundaries[i]) {
					regs->ARM_pc = (uint32_t) item->trampoline_instructions + item->trampoline_boundaries[i];
					// 이거 안맞을수도 있지 않나...  => 아니네.. ㅋ 맞음. ㄴ
					return true;
				}
			}
			break;
		case ACTION_DISABLE: // unhook 일때
			offset = regs->ARM_pc - (int) item->trampoline_instructions;
			for (i = 0; i < item->count; ++i) {
				if (offset == item->trampoline_boundaries[i]) {
					regs->ARM_pc = CLEAR_BIT0(item->target_addr) + item->orig_boundaries[i];
					return true;
				}
			}
			break;
	}

	return false;
}

static void processThreadPC(pid_t tid, struct inlineHookItem *item, int action)
{
	struct pt_regs regs;

	if (ptrace(PTRACE_GETREGS, tid, NULL, &regs) == 0) {  //PTRACE_GETREGS :해당 thread의 레지스터들을 받아옴
		if (item == NULL) { // ?? 이런경우가 있나? 적어도 inlinehook일땐 없음
			int pos;

			for (pos = 0; pos < info.size; ++pos) {
				if (doProcessThreadPC(&info.item[pos], &regs, action) == true) {
					break;
				}
			}
		}
		else {
			doProcessThreadPC(item, &regs, action);  // ACTION_ENABLE inline hook 일때.
		}

		ptrace(PTRACE_SETREGS, tid, NULL, &regs);
	}
}

/*
* 아마 thread전체 중지 시키는 거일듯..
* ACTION_ENABLE => inlinehook 할때. 
*/
static pid_t freeze(struct inlineHookItem *item, int action)
{
	int count;
	pid_t tids[1024];
	pid_t pid;

	pid = -1;
	count = getAllTids(gettid(), tids); // 현재 tid 빼고 전체 tid를 tids에 저장
	if (count > 0) {
		pid = fork(); // fork하지 않고 thread에 attach하면 stop signal이 전체에 공유되니까 이렇게 한듯.. 

		if (pid == 0) {  // 자식코드
			int i;

			for (i = 0; i < count; ++i) {
				if (ptrace(PTRACE_ATTACH, tids[i], NULL, NULL) == 0) {
					waitpid(tids[i], NULL, WUNTRACED); // PTRACE_ATTACH 한다고 해당 thread가 바로 중지하는게 아니어서 waitpid로 기다리는게 정석.
					// * 아래가 핵심
					processThreadPC(tids[i], item, action);
				}
			}
			
			raise(SIGSTOP); // 자기자신에게 sigstop signal 보내서, 부모 process가 깨어나길 기다림. 

			// 아래는 parent의 unfreeze 호출시 진행됨.
			for (i = 0; i < count; ++i) {
				ptrace(PTRACE_DETACH, tids[i], NULL, NULL);
			}

			raise(SIGKILL);
		}

		else if (pid > 0) { // 부모 코드
			waitpid(pid, NULL, WUNTRACED);  // waitpid 함수는 인수로 주어진 pid 번호의 자식프로세스가 종료되거나, 시그널 함수를 호출하는 신호가 전달될때까지 waitpid 호출한 영역에서 일시 중지 된다.
			// WUNTRACED는 child가 stop하면 return 함. 
		}
	}

	return pid;
}

static void unFreeze(pid_t pid)
{
	if (pid < 0) {
		return;
	}

	kill(pid, SIGCONT);
	wait(NULL);
}

// function 이 exe 가능한 건지 체크 하는거 인듯.. 에러 방지용
static bool isExecutableAddr(uint32_t addr)
{
	FILE *fp;
	char line[1024];
	uint32_t start;
	uint32_t end;

	// 역시 maps open 하네.. 아 그리고 mem 파일에서 dump 가능하다고 했지.. ( 디버거에서 dump 하는거 보다.. 성능? 때문이었나?)
	// mem 내용 어디서 봤지.... dump 쪽 인가? 저장 해놨나
	fp = fopen("/proc/self/maps", "r");
	if (fp == NULL) {
		return false;
	}

	
	// maps line 단위로 읽어서.. x 권한 있으면 start addr 랑 end addr 문자 파싱해서
	// addr가 그안에 속하는지 check.. 
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "r-xp") || strstr(line, "rwxp")) {
			start = strtoul(strtok(line, "-"), NULL, 16);
			end = strtoul(strtok(NULL, " "), NULL, 16);
			if (addr >= start && addr <= end) {
				fclose(fp);
				return true;
			}
		}
	}

	fclose(fp);

	return false;
}

// 이미 info에 등록된 건지 check. 
static struct inlineHookItem *findInlineHookItem(uint32_t target_addr)
{
	int i;

	for (i = 0; i < info.size; ++i) {
		if (info.item[i].target_addr == target_addr) {
			return &info.item[i];
		}
	}

	return NULL;
}

// item 저장을 위해 info에서 item 주소 하나 가져오는 함수. 
static struct inlineHookItem *addInlineHookItem() {
	struct inlineHookItem *item;

	// 이미 info에 자리가 없으면.. 끝
	if (info.size >= 1024) {
		return NULL;
	}

	// 그냥 만들어진 배열에서 주소 하나 가져와서 전달하는게.. 전부.. 
	item = &info.item[info.size];
	++info.size;

	return item;
}

static void deleteInlineHookItem(int pos)
{
	info.item[pos] = info.item[info.size - 1];
	--info.size;
}

/*
* target_addr : 타겟 함수 -> 이후 프롤로그 변형 될듯.. 
* new_addr : 후킹 함수 + proto_addr 호출 함수 일듯.. 
* proto_addr : [ 원본 함수 시작 +  원본 함수 복귀 코드 존재 할듯..  ]
*/
enum ele7en_status registerInlineHook(uint32_t target_addr, uint32_t new_addr, uint32_t **proto_addr)
{
	struct inlineHookItem *item; // 아이템 저장 공간..

	// x 권한 있는지 maps 보고 판단.
	if (!isExecutableAddr(target_addr) || !isExecutableAddr(new_addr)) {
		return ELE7EN_ERROR_NOT_EXECUTABLE;
	}
	// 이미 등록 된 것인지 check. 
	item = findInlineHookItem(target_addr);
	// 아 맞네.. 이미 등록 되어 있다면 상태 알려줌.. 
	if (item != NULL) {
		if (item->status == REGISTERED) {
			return ELE7EN_ERROR_ALREADY_REGISTERED;
		}
		else if (item->status == HOOKED) {
			return ELE7EN_ERROR_ALREADY_HOOKED;
		}
		else {
			return ELE7EN_ERROR_UNKNOWN;
		}
	}

	item = addInlineHookItem(); // 그냥 info에 있는 item 배열에서 주소 하나 가져오는 것 (물론 index는 맨 마지막꺼/ )

	// 받은 파라메터 대로 저장. 
	item->target_addr = target_addr;
	item->new_addr = new_addr;
	item->proto_addr = proto_addr;

	// 타겟의 prologue 부분을 저장하는 코드라고 보여짐. ( 근데 arm일땐 3개 thumb 일땐 4개인가?? 아.. prologue형태가 여러 가지 인가봄.. 아마 최대치를 저장하는듯..)
		// 이론에서 본건 inst 딱 2개인데.. 총 8바이트쯤?
	item->length = TEST_BIT0(item->target_addr) ? 12 : 8; // 암일때 8 ( inst2개 ) thumb일때 12( 6개 inst)
		// thumb일때 code section 에서 함수 주소가 홀수가 되나? => thumb이어도 짝수고, bx에서 하드코딩 주소만 +1 되는게 아닌가??
	item->orig_instructions = malloc(item->length);
	memcpy(item->orig_instructions, (void *) CLEAR_BIT0(item->target_addr), item->length);
		// 뭐냐 타겟 주소 짝수로 만들고 istruction 몇개 가져와서 저장. ( 왜 짝수로 했지? 아.. bx같은걸로 이미 mode 전환되서 오나?)
		// orig_instructions은 바로위에서 malloc으로 공간 만듬.. 
		// thumb일땐12byte즉 6개 inst가져오네..


	// mmap으로 공간 받네.. 아마 heap이아니라 execute 가능한 공간이어야 하기 때문인듯? page 단위로 받아야 하고.. 당연히..
	// 권한이 rwx 이고,  PAGE_SIZE 만큼.. 즉 1 page 받는 코드 같다 .. lengh는 byte 단우ㅏ,, 
	// MAP_ANONYMOUS + MAP_PRIVATE : https://stackoverflow.com/questions/34042915/what-is-the-purpose-of-map-anonymous-flag-in-mmap-system-call
	// 그냥 실행 권한 있는 영역 할당 받은거로 보면된다. 
	item->trampoline_instructions = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
	
	// ** 핵심 코드 **
	// 트램펄린 코드 만들어서 trampoline_instructions에 저장한다. { 프롤로그 + 원본 점프 } 이떄 lr이나 pc 또는 addr 조정이 필요한경우
	// 해당 내용도 조정해준다. ( 이부분들은 함수 중간을 후킹 했을때.)
	relocateInstruction(item->target_addr, item->orig_instructions, item->length, item->trampoline_instructions, item->orig_boundaries, item->trampoline_boundaries, &item->count);
	// 상태 변경
	item->status = REGISTERED;

	return ELE7EN_OK;
}

/*
* pos는 info의 아이템 배열의 index
*/
static void doInlineUnHook(struct inlineHookItem *item, int pos)
{
	// 타겟 addr 페이지 권한 rwx로 변경
	mprotect((void *) PAGE_START(CLEAR_BIT0(item->target_addr)), PAGE_SIZE * 2, PROT_READ | PROT_WRITE | PROT_EXEC);
	memcpy((void *) CLEAR_BIT0(item->target_addr), item->orig_instructions, item->length);
	mprotect((void *) PAGE_START(CLEAR_BIT0(item->target_addr)), PAGE_SIZE * 2, PROT_READ | PROT_EXEC);
	munmap(item->trampoline_instructions, PAGE_SIZE);
	free(item->orig_instructions);

	deleteInlineHookItem(pos);

	cacheflush(CLEAR_BIT0(item->target_addr), CLEAR_BIT0(item->target_addr) + item->length, 0);
}

enum ele7en_status inlineUnHook(uint32_t target_addr)
{
	int i;

	for (i = 0; i < info.size; ++i) {
		if (info.item[i].target_addr == target_addr && info.item[i].status == HOOKED) {
			pid_t pid;

			pid = freeze(&info.item[i], ACTION_DISABLE);

			doInlineUnHook(&info.item[i], i);

			unFreeze(pid);

			return ELE7EN_OK;
		}
	}

	return ELE7EN_ERROR_NOT_HOOKED;
}

void inlineUnHookAll()
{
	pid_t pid;
	int i;

	pid = freeze(NULL, ACTION_DISABLE);

	for (i = 0; i < info.size; ++i) {
		if (info.item[i].status == HOOKED) {
			doInlineUnHook(&info.item[i], i);
			--i;
		}
	}

	unFreeze(pid);
}


/*
* 이게 핵심!
*/
static void doInlineHook(struct inlineHookItem *item)
{
	// target 영영 page 를 권한 세팅 mprotect api 가 아마 page 단위로 세팅 해야 하는듯?
	mprotect((void *) PAGE_START(CLEAR_BIT0(item->target_addr)), PAGE_SIZE * 2, PROT_READ | PROT_WRITE | PROT_EXEC);

	// proto_addr가 트램펄린 코드 주소 전달해주는 거였네.. 
	// target이 thumb면 트램펄린 주소도 thumb으로 주네.. 
	// 아마 코드는 짝수에 있지만 하드코딩 주소는 홀수라면 cpu가 알아서 마지막 bit 초기화 하고 뛴다고 본거 같네.
	if (item->proto_addr != NULL) {
		*(item->proto_addr) = TEST_BIT0(item->target_addr) ? (uint32_t *) SET_BIT0((uint32_t) item->trampoline_instructions) : item->trampoline_instructions;
	}
	
	// 이게 target쪽 트램펄린 세팅.
	if (TEST_BIT0(item->target_addr)) { // thumb일때.
		int i;

		i = 0;
		// 이건 뭔코드지.. ?????
		if (CLEAR_BIT0(item->target_addr) % 4 != 0) {  // 뭔가 align이 안되어있는 상황?
			((uint16_t *) CLEAR_BIT0(item->target_addr))[i++] = 0xBF00;  // NOP
		}
		// 총 4개 inst 8byte // thumb에서 12byte 백업은 왜 하는지 전혀 모르겠다. 중간에 NOP 넣는것도.. 
		// thumbv8 
		((uint16_t *) CLEAR_BIT0(item->target_addr))[i++] = 0xF8DF;
		((uint16_t *) CLEAR_BIT0(item->target_addr))[i++] = 0xF000;	// LDR.W PC, [PC]  => 위 까지 F8DFF000
		((uint16_t *) CLEAR_BIT0(item->target_addr))[i++] = item->new_addr & 0xFFFF; // 이건 그냥 주소 분할해서 넣은거고.. 주소 4byte.
		((uint16_t *) CLEAR_BIT0(item->target_addr))[i++] = item->new_addr >> 16;
	}
	else { // arm 일때. 역시 알던대로 inst 2개 쓰네, jmp addr는 new function 주소 이고
		((uint32_t *) (item->target_addr))[0] = 0xe51ff004;	// LDR PC, [PC, #-4]
		((uint32_t *) (item->target_addr))[1] = item->new_addr;
	}

	// 수정한 영역 권한 다시 설정
	mprotect((void *) PAGE_START(CLEAR_BIT0(item->target_addr)), PAGE_SIZE * 2, PROT_READ | PROT_EXEC);
	
	// item 상태 설정. 
	item->status = HOOKED;
	// 이게 핵심 중 하나.. target의 instruction 수정했지만 memory에 적용되지 않앟을수 있어서 cacheflush 해야 함. 
	cacheflush(CLEAR_BIT0(item->target_addr), CLEAR_BIT0(item->target_addr) + item->length, 0);
}

/*
* 이거 자체는 별내용은 없음. sub루틴이 중요
*/
enum ele7en_status inlineHook(uint32_t target_addr)
{
	int i;
	struct inlineHookItem *item;

	// 등록이 미리 되어 있는지 확인.
	item = NULL;
	for (i = 0; i < info.size; ++i) {
		if (info.item[i].target_addr == target_addr) {
			item = &info.item[i];
			break;
		}
	}
	// 등록 먼저 안했으면 에러 
	if (item == NULL) {
		return ELE7EN_ERROR_NOT_REGISTERED;
	}

	// 아직 hooked 상태가 아니면?
	if (item->status == REGISTERED) {
		pid_t pid;

		pid = freeze(item, ACTION_ENABLE);  // 이게 멀티 쓰레드 때문인듯.. 이때 pid는 자식 프로세스

		doInlineHook(item);

		unFreeze(pid);

		return ELE7EN_OK;
	}
	else if (item->status == HOOKED) {
		return ELE7EN_ERROR_ALREADY_HOOKED;
	}
	else {
		return ELE7EN_ERROR_UNKNOWN;
	}
}

void inlineHookAll()
{
	pid_t pid;
	int i;

	pid = freeze(NULL, ACTION_ENABLE);

	for (i = 0; i < info.size; ++i) {
		if (info.item[i].status == REGISTERED) {
			doInlineHook(&info.item[i]);
		}
	}

	unFreeze(pid);
}
