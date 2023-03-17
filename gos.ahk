#SingleInstance ignore
#NoEnv
#Persistent
#If ((CheckCrmp()) & (game_loaded = 1))
#MaxMem, 256

DetectHiddenWindows, On
OnError("ExcError")
OnExit("ExitGH")

OnMessage(0x11, "WM_QUERYENDSESSION")
OnMessage(0x201, "WM_LBUTTONDOWN")

WM_LBUTTONDOWN(wParam, lParam, msg, hwnd) {
	Global hCaption, MainWID
	
	if GetKeyState("LButton", "P")
	{
		MouseGetPos, , , , OutputVarControl, 4
		WinGet, OutputWin, ID, A

		ControlGetText, OutputCtrl, % OutputVarControl, ahk_id %mainwid%	
		if (outputctrl = "__`n`nСвернуть")
		{
			gosub GuiMinimize
			return
		}
		if (outputctrl = "x`n`nЗакрыть")
		{
			gosub GuiClose
			return
		}
	}
	
	If ((hwnd = hCaption) or (outputctrl = MainWID)) {
		PostMessage, 0xA1, 2,,, ahk_id %MainWID%
		return
	}
}

Menu, Tray, NoStandard
SetBatchLines -1

is_sub = 1
start_argument1 = %1%
start_argument2 = %2%
start_argument3 = %3%

progressText(text) {
	GuiControl, 1:, progressText, % text
}

SearchProcess(NameOrPID, StartAddr, EndAddr, pTarget, cbTarget = 4, cAddrs = 100)
{
    static Code := 0, MFunc, Len, Page := 0x1000, mbi, mbiSize
    static stateOffset, protOffset, regSizeOffset
    static Rights := 0x410  ; PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
    static MEM_COMMIT := 0x1000, PAGE_READWRITE := 4, PAGE_READONLY := 2
    static PAGE_WRITECOPY := 0x08
    static BufSize := 0x100000  ; 1 MB. Размер буфера для чтения из процесса.
    If (Code != 0)  ; Если не первый вызов, то машинный код уже готов.
        GoTo Process
    If (A_PtrSize = 8) {    ; x64
        mbiSize := 48, stateOffset := 32, protOffset := 36, regSizeOffset := 24
        Code = 
        ( Join LTrim
        48894C240848895424104C894424184C894C2420555357564889E54883EC08488B
        7D288B4D308B5540488B5D48C745F800000000FFCA29D1783B488B7538ACF2AE75
        325189D1F3A60F94C04829D14801CF5984C0741B488D47FF482B45284803455848
        89034883C308FF45F8FF4D50740485C975C58B45F8488D65005E5F5B5DC3
        )
    }
    Else {      ; x86
        mbiSize := 28, stateOffset := 16, protOffset := 20, regSizeOffset := 12
        Code = 
        ( Join LTrim
        5553575689E583EC048B7D148B4D188B55208B5D24C745FC000000004A29D17833
        8B751CACF2AE752B5189D1F3A60F94C029D101CF5984C074168D47FF2B45140345
        2C890383C304FF45FCFF4D28740485C975CD8B45FC89EC5E5F5B5DC21C00
        )
    }
    Len := StrLen(Code) // 2
    ; Память под машинный код.
    MFunc := DllCall("VirtualAlloc", "ptr", 0, "ptr", Len
                                   , "uint", 0x3000, "uint", 0x40, "ptr")
    Loop, % Len
        NumPut("0x" . SubStr(Code, A_Index * 2 - 1, 2), MFunc + 0
                                     , A_Index - 1, "uchar")
    VarSetCapacity(mbi, mbiSize) ; Структура MEMORY_BASIC_INFORMATION
Process:
    Process, Exist, %NameOrPID%
    If !(PID := ErrorLevel) {
        MsgBox, Процесс не найден
        Return 0
    }
    hProcess := DllCall("OpenProcess", "uint", Rights, "int", False, "uint", PID, "ptr")
    If(!hProcess) {
        MsgBox, Не удалось открыть процесс.
        Return 0                           
    }
    VarSetCapacity(AddrBuf, A_PtrSize * cAddrs, 0) ; Буфер для найденных адресов.
    VarSetCapacity(Buf, BufSize) ; Буфер для считанной из процесса памяти.
    CurAddr := (StartAddr // Page) * Page ; Текущий адрес. Округлить до начала страницы.
    pAddrBuf := &AddrBuf ; Указатель на свободное место в буфере адресов.
    FoundAll := 0 ; Всего найдено.

    While(CurAddr < EndAddr) {
        BytesRet := DllCall("VirtualQueryEx", "ptr", hProcess, "ptr", CurAddr
                                            , "ptr", &mbi, "uint", mbiSize, "ptr")
        If (BytesRet = 0) {
            CurAddr += Page
            Continue
        }
        RegionSize := NumGet(mbi, regSizeOffset, "uptr")
        ; Если память не выделена (адреса свободны или только зарезервированы),
        ; пропускаем весь этот регион.
        If (NumGet(mbi, stateOffset, "uint") != MEM_COMMIT) {
            CurAddr += RegionSize
            If (A_PtrSize = 4 && CurAddr > 0xFFFFFFFF)
                GoTo Done
            Continue
        }
        Protect := NumGet(mbi, protOffset, "uint")
        ; Проверять только память для записи и чтения (данные).
        If !(Protect = PAGE_READWRITE || Protect = PAGE_WRITECOPY
                                      || Protect = PAGE_READONLY) {
            CurAddr += RegionSize
            If (A_PtrSize = 4 && CurAddr > 0xFFFFFFFF)
                GoTo Done
            Continue
        }
        While(RegionSize) { ; Считывание в буфер и поиск в нём.
            ReadSize := BufSize < RegionSize ? BufSize : RegionSize
            RegionSize -= ReadSize
            Ret := DllCall("ReadProcessMemory", "ptr", hProcess, "ptr", CurAddr
                                              , "ptr", &Buf, "ptr", ReadSize
                                              , "ptr *", BytesRead, "int")
            If (!Ret) { ; Если ошибка чтения, идём дальше.
                CurAddr += ReadSize
                Continue
            }
            ; Вызов машинной функции для поиска.
            Found := DllCall(MFunc, "ptr", &Buf, "ptr", BytesRead
                                  , "ptr", pTarget, "uint", cbTarget
                                  , "ptr", pAddrBuf, "uint", cAddrs - FoundAll
                                  , "ptr", CurAddr, "uint")
            CurAddr += ReadSize
            If (Found = 0) {
                Continue
            }
            If ((FoundAll += Found) < cAddrs) {
                pAddrBuf += Found * A_PtrSize
                Continue
            }
            Goto Done
        }
    }
	Done:
    DllCall("CloseHandle", "ptr", hProcess)
    If (FoundAll = 0)
        Return 0
    Array := []
    Loop, %FoundAll%
        Array.Insert(NumGet(&AddrBuf+(A_PtrSize * (A_Index - 1)), 0, "uptr"))
    Return Array    
}

ExitGH() {
	global
	process, close, iexplore.exe
	try DestroyAllVisual()
	DllCall("ShutdownBlockReasonDestroy", "ptr", A_ScriptHwnd)
	gosub GuiClose
	IniWrite, 0, %A_ProgramFiles%\GOS Helper\config.ini, work, status
}

if (start_argument1 != "shell") {
	if (gh.getState()) {
		MsgBox, 0, GOS Helper, GOS Helper уже запущен.
		exitapp
	}
}

if (!A_IsAdmin) {
	Run, *RunAs %A_ScriptFullPath% `"%start_argument1%`" `"%start_argument2%`" `"%start_argument3%`",, UseErrorLevel
	exitapp
}

root = %A_ProgramFiles%\GOS Helper
FileCreateDir, %root%
SetWorkingDir, %root%

; VARS
global err_code := 0, mainwid, urltologo, path_chatlog, path_cfg, text_in_chatlog, chat_queue, executeFuncWas, servAttempts := 0, gh_loaded := 0, ovx, ovy, game_loaded := 0, ovfontname, ovsize, zanes := 1, path_screens, arimgur, fraction, tag, gh_online := "-", ghapi_url, ghapi_is_online := 0, ghapi, playername, _cmds, release, ghapi_token, camlist, patrol_with, patrol_enemy, _mapcity, dop_overlay_text, not_afk_time_timer_sec, afk_overlay_id, owc := 0, clist, is_authed := 0, arsavescreens, bl_nickname, bl_date, bl_server, supportresps, suphelper, support_questions_ov, sup_overlay_id1, sup_overlay_id2, sup_overlay_id3, sup_overlay_id4, sup_overlay_id5, started_from_ghlauncher := 0, Suphelper_WriteResponses, sh_questions, cancelchat := 0, cancelchat_msg := 0, chat_forcibly
global vkmsg := []
global blacklist := []
global ghtruck_history := "", ghtruck_income := 0, ghtruck_expense := 0

global msg_overlay_error1 := "%t По какой-то причине оверлей не захотел показываться, я продолжу работу без него."
global msg_overlay_error2 := "%t Если он Вам крайне необходим, то попробуйте: выйти из игры, перезапустить GH, запустить игру с GH."

pToken:=Gdip_Startup()
global Button:=[]
global X_Position_Edit,Y_Position_Edit,W_Position_Edit,H_Position_Edit,Name_Edit,Options_Edit,Title_Edit,Bitmap_Edit

not_afk_time_timer_sec = 1200

NR_temp =0 ; init
TimeOut = 100 ; milliseconds to wait before deciding it is not responding - 100 ms seems reliable under 100% usage
; WM_NULL =0x0000
; SMTO_ABORTIFHUNG =0x0002
Global NR_temp, TimeOut, SAMP_WID

global fraclist := "Гражданин (Citizen)|Армия МВ (Army_MV)|Армия ВМФ (Army_VMF)|Администрация Президента (Admin_President)|Администрация Батырево (Admin_Batirevo)|Полиция Южного (Police_South)|Полиция Арзамаса (Police_Arzamas)|ФСБ (FBI)|СМИ (SMI)|ГИБДД (GIBDD)|Инструкторы (Instructor)|ЦГБ Арзамаса (CGB_Arzamas)|ЦГБ Южного (CGB_South)"
global dwSAMP, hGTA
vkmsg[0] := ""

path_chatlog = %A_MyDocuments%\GTA San Andreas User Files\SAMP\chatlog.txt
path_screens = %A_MyDocuments%\GTA San Andreas User Files\SAMP\screens
path_cfg = %A_MyDocuments%\GTA San Andreas User Files\SAMP\sa-mp.cfg

need_installer_version = 06.01.21 ; установщик

; Информация об обновлении
release := "1.4"

; Список команд
cmd_list =
(
{FFFFFF}Список встроенных команд:
{4169E1}/abbrev {FFFFFF}- список сокращенных команд.
{4169E1}/ghtruck {FFFFFF}- информация о доходах/расходах для дальнобойщиков.
{4169E1}/motionblur <0/1> {FFFFFF}- размытость при движении на большой скорости как в одиночной игре.	
{4169E1}/ovhelp {FFFFFF}- настройки оверлея.
{4169E1}/quit {FFFFFF}- стопроцентный и быстрый выход из игры.
{4169E1}/relog {FFFFFF}- перезапустить игру на выбранный сервер (аналогично как /re).
{4169E1}/setnick <ник> {FFFFFF}- изменит ник при следующем заходе в игру.
{4169E1}/setweather <id> {FFFFFF}- изменит погоду (только для вас).
{4169E1}/updatelist {FFFFFF}- список обновлений (аналогично как /ul).
{4169E1}/vkmsg {FFFFFF}- вкл./выкл. уведомления о новых сообщениях ВКонтакте.

{FFFFFF}Версия программы:{4169E1} %release%{FFFFFF}.
)

_cmds = 
(
testsupov
setweather
motionblur
abbrev
qvm
vreply
qvv
playvm
sendvm
quit
setnick
ul
updatelist
dev
devdwsamp
devreload
gh
vkmsg
replyids
opendialog
reply
arinvite
aruninvite
arfrank
arfuninvite
arrank
cancelpost
relog
адвокат1
адвокат2
адвокат3
удостоверение
присяга
разборкам4
сборкам4
клятва
лечить1
лечить2
лечитьнарко1
лечитьнарко2
лечитьорви
лечитьхобл
лечитьхп
арест
взять
кпут
обыск
розыск
штраф
прлиц
интервью1
интервью2
интервью3
погода
эфир1
эфир2
эфир3
куфы
уд
suphelp
supclear
ovhelp
ovmove
ovfont
ovsize
ovstandard
ghtruck
ghonline
)

ghlang_help =
(
Справка по скриптовому языку GOS Helper Language, версии %release%.
На самом деле тут не так сложно, как кажется. Главное вчитываться в текст. Пишу как можно понятнее.

Коротко о строении кода:
  - Каждая команда разделяется новой строкой (новая команда - новая строка).
  - Соблюдать регистр букв в названии команд не обязательно (заглавные и строчные буквы).
  - Соблюдать постановку запятых в названии команд крайне обязательно (запятыми обозначаются аргументы команды).
  - Если записана какая-то переменная, то Вы можете воспользоваться ей, обозначив ее "$" в начале названия (например: $id, $text и т.п).

Обозначения в документации:
  - Аргументы в <угловых> скобках обязательны. Если они в [квадратных] скобках, то они необязательны.
  - Аргумент flag обозначает два варианта аргумента: 1 - true, 0 - false.

Список команд по алфавиту. Для быстрой навигации по командам используйте Ctrl+F.
  -> chat.show, <аргумент1>
  -> chat.send, <аргумент1> [, flag(без очереди)]
  -> chat.input, <аргумент1>, <аргумент2> [, flag(пароль?)]
  -> dialog.standard, <аргумент1>
  -> dialog.list, <аргумент1>
  -> sleep, <аргумент1>
  -> nickname.getByID, <аргумент1>, <аргумент2>

Команда chat.show, <аргумент1>
  Отобразит локальное сообщение в чат (как AddChatMessage в UDF и т.п.).
  В первом аргументе вводится текст, который будет отображаться Вам. Обратите внимание на ньюансы.
    Текст `%r будет сразу же заменен на {FF6347} (красный шрифт).
    Текст `%w будет сразу же заменен на {FFFFFF} (белый шрифт).
    Текст `%b будет сразу же заменен на {4169E1} (синий шрифт, цвет GH).
    Текст `%t будет сразу же заменен на {4169E1}[GOS Helper]{FFFFFF} (тег GH в чате).
  Пример использования команды:
    chat.show, `%wПривет, `%bмир!
    chat.show, Привет, мир!

Команда chat.send, <аргумент1> [, flag(без очереди)]
  Отправит в чат сообщение через память игры.
  В первом аргументе вводится текст, который нужно отправить в чат.
  Во втором аргументе (flag) вводится: либо 1, либо 0. Если Вам необходимо отправить сообщение без задержки, то используйте 1. Если с задержкой, то 0.
    GOS Helper имеет встроенную систему задержки сообщений, чтобы избежать "Не флудите!" от сервера. Если Вам нужно в любом случае отправить это сообщение без задержки, то указывайте 1.
    По умолчанию значение этого аргумента равно 0.
  Пример использования команды:
    chat.send, /me достал паспорт из кармана
    chat.send, /me достал мед.карту из кармана, 0
    chat.send, /me достал пакет лицензий, 1

Команда chat.input, <аргумент1>, <аргумент2> [, flag(пароль?)]
  Отобразит локальный диалог с текстом и полем для ввода.
  В первом аргументе вводится название переменной, в которую будет записано то, что ввел пользователь в диалоге.
  Во втором аргументе вводится текст, который будет показан в диалоге. Обратите внимание на ньюансы.
    Текст `%r будет сразу же заменен на {FF6347} (красный шрифт).
    Текст `%w будет сразу же заменен на {FFFFFF} (белый шрифт).
    Текст `%b будет сразу же заменен на {4169E1} (синий шрифт, цвет GH).
  В третьем аргументе (flag) вводится: либо 0, либо 1. Если Вам нужно скрыть введенные данные, то указывайте 1.
  По умолчанию значение этого аргумента равно 0.
  Пример использование команды:
    chat.input, ID, Укажите ID игрока
    chat.input, ID, Укажите статью, 0
    chat.input, ID, Укажите пароль от базы данных, 1

Команда dialog.standard, <аргумент1>
  Отобразит локальный диалог с текстом и кнопкой "Закрыть".
  В первом аргументе вводится текст, который будет показан в диалоге. Обратите внимание на ньюансы.
    Текст \n будет заменен на переход на новую строку.
    Текст \r будет заменен на табуляцию.
    Текст `%r будет сразу же заменен на {FF6347} (красный шрифт).
  Пример использования команды:
    dialog.standard, Этот текст появится в диалоге.
    dialog.standard, Второй пример с `%rкрасным{FFFFFF} текстом.

Команда dialog.list, <аргумент1>
  Отобразит локальный диалог с таблицей. Подробнее об особенностях диалога тут: sampwiki.blast.hk/wiki/Dialog_Styles (id диалога: 5).
  В первом аргументе вводится текст, который будет показан в диалоге.
    Текст \n будет заменен на переход на новую строку.
    Текст \r будет заменен на табуляцию.
    Текст `%r будет сразу же заменен на {FF6347} (красный шрифт).s
  Пример использования команды:
    dialog.list, {FFFFFF}Доходы/расходы\t{FFFFFF}Описание\n\n1500P\tПокупка телефона.W

Команда sleep, <аргумент1>
  Установка задержки.
  В первом аргументе указывается задержка в миллисекундах.
  Пример использования команды:
    sleep, 3000
    sleep, 500
    sleep, 1500

Команда nickname.getByID, <аргумент1>, <аргумент2>
  Записывает в переменные имя и фамилию игрока по ID.
  В первом аргументе указывается название переменной, в которую будет записана информация. Обратите внимание на ньюансы.
    Пример: Указав в названии переменной test, имя игрока будет записано в переменную $test_name, а фамилия в $test_family. В самой же переменной $test будут записаны имя и фамилия игрока, но уже вместе, разделенные пробелом.
  Во втором аргументе указывается ID игрока, о котором нужно получить информацию в переменные.
  Пример использования команды:
    nickname.getByID, info, 348
    nickname.getByID, player, 201
    nickname.getByID, target, 503

Команда screenshot
  Делает скриншот игры, методом нажатия на F8 в игре.
  Не требует аргументов.
  Пример использования команды:
    screenshot
)

_mapcity =
(
2293|-2341|Южный|1000
2040|1901|Батырево|700
-89|24|Москва-сити|400
217|1069|Арзамас|1000
)

; Для дальнобойщиков
global td_poezdki := 0
global td_gruz := 0
global td_dengi := 0

; UDF
global hGTA := 0x0
global dwGTAPID := 0x0
global dwSAMP := 0x0
global pMemory := 0x0
global pParam1 := 0x0
global pParam2 := 0x0
global pParam3 := 0x0
global pParam4 := 0x0
global pParam5 := 0x0
global pInjectFunc := 0x0
global iRefreshHandles := 0
global pInjectFunc := 0x0
global nZone := 1
global nCity := 1
global bInitZaC := 0
global iRefreshScoreboard := 0
global oScoreboardData := ""
global iRefreshHandles := 0
global iUpdateTick := 2500      ;time in ms, used for getPlayerNameById etc. to refresh data
global bCheckSizeOnce := 1

global SAMP_INFO_OFFSET                     := 0x21A0F8
global SAMP_PPOOLS_OFFSET                   := 0x3CD
global SAMP_PPOOL_PLAYER_OFFSET             := 0x18
global SAMP_SLOCALPLAYERID_OFFSET           := 0x4
global SAMP_ISTRLEN_LOCALPLAYERNAME_OFFSET  := 0x1A
global SAMP_SZLOCALPLAYERNAME_OFFSET        := 0xA
global SAMP_PSZLOCALPLAYERNAME_OFFSET       := 0xA
global SAMP_PREMOTEPLAYER_OFFSET            := 0x2E
global SAMP_ISTRLENNAME___OFFSET            := 0x1C
global SAMP_SZPLAYERNAME_OFFSET             := 0xC
global SAMP_PSZPLAYERNAME_OFFSET            := 0xC
global SAMP_ILOCALPLAYERPING_OFFSET         := 0x26
global SAMP_ILOCALPLAYERSCORE_OFFSET        := 0x2A
global SAMP_IPING_OFFSET                    := 0x28
global SAMP_ISCORE_OFFSET                   := 0x24
global SAMP_ISNPC_OFFSET                    := 0x4
global SAMP_SZIP_OFFSET                     := 0x20
global SAMP_SZHOSTNAME_OFFSET               := 0x121
global SAMP_DIALOG_STRUCT_PTR               := 0x26E898

global SAMP_PLAYER_MAX                      := 1004
global SIZE_SAMP_CHATMSG            	    := 0xFC

; SAMP Addresses
global ADDR_SAMP_INCHAT_PTR            := 0x21A10C
global ADDR_SAMP_INCHAT_PTR_OFF        := 0x55
global ADDR_SAMP_USERNAME              := 0x219A6F
global ADDR_SAMP_CHATMSG_PTR           := 0x21A0E4
global ADDR_SAMP_SHOWDLG_PTR           := 0x21A0B8
global FUNC_SAMP_SENDCMD               := 0x698C0
global FUNC_SAMP_SENDSAY               := 0x5A00
global FUNC_SAMP_ADDTOCHATWND          := 0x64520
global FUNC_SAMP_SHOWGAMETEXT          := 0xA0D10
global FUNC_SAMP_PLAYAUDIOSTR          := 0x66920
global FUNC_SAMP_STOPAUDIOSTR          := 0x66520
global FUNC_SAMP_SHOWDIALOG				:= 0x6F8C0
global FUNC_UPDATESCOREBOARD           := 0x8F00

; GTA Addresses
global ADDR_ZONECODE                   := 0xA49AD4
global ADDR_POSITION_X                 := 0xB6F2E4
global ADDR_POSITION_Y                 := 0xB6F2E8
global ADDR_POSITION_Z                 := 0xB6F2EC
global ADDR_CPED_PTR                   := 0xB6F5F0
global ADDR_CPED_HPOFF                 := 0x540
global ADDR_CPED_ARMOROFF              := 0x548
global ADDR_VEHICLE_PTR                := 0xBA18FC
global ADDR_VEHICLE_HPOFF              := 0x4C0
global ADDR_CPED_MONEY                 := 0xB7CE50
global ADDR_CPED_INTID                 := 0xA4ACE8
global ADDR_VEHICLE_DOORSTATE          := 0x4F8
global ADDR_VEHICLE_ENGINESTATE        := 0x428
global ADDR_VEHICLE_LIGHTSTATE         := 0x584
global ADDR_VEHICLE_MODEL              := 0x22
global ADDR_VEHICLE_TYPE               := 0x590
global ADDR_VEHICLE_DRIVER             := 0x460

global ERROR_OK                             := 0
global ERROR_PROCESS_NOT_FOUND              := 1
global ERROR_OPEN_PROCESS                   := 2
global ERROR_INVALID_HANDLE                 := 3
global ERROR_MODULE_NOT_FOUND               := 4
global ERROR_ENUM_PROCESS_MODULES           := 5
global ERROR_ZONE_NOT_FOUND                 := 6
global ERROR_CITY_NOT_FOUND                 := 7
global ERROR_READ_MEMORY                    := 8
global ERROR_WRITE_MEMORY                   := 9
global ERROR_ALLOC_MEMORY                   := 10
global ERROR_FREE_MEMORY                    := 11
global ERROR_WAIT_FOR_OBJECT                := 12
global ERROR_CREATE_THREAD                  := 13

; ######################### Структуры диалога #########################

global DIALOG_STYLE_MSGBOX			        := 0
global DIALOG_STYLE_INPUT 			        := 1
global DIALOG_STYLE_LIST			        := 2
global DIALOG_STYLE_PASSWORD		        := 3
global DIALOG_STYLE_TABLIST			        := 4
global DIALOG_STYLE_TABLIST_HEADERS	        := 5

global SAMP_DIALOG_PTR1_OFFSET				:= 0x1C
global SAMP_DIALOG_LINES_OFFSET 			:= 0x44C
global SAMP_DIALOG_INDEX_OFFSET				:= 0x443
global SAMP_DIALOG_BUTTON_HOVERING_OFFSET	:= 0x465
global SAMP_DIALOG_BUTTON_CLICKED_OFFSET	:= 0x466
global SAMP_DIALOG_PTR2_OFFSET 				:= 0x20
global SAMP_DIALOG_LINECOUNT_OFFSET			:= 0x150
global SAMP_DIALOG_OPEN_OFFSET				:= 0x28
global SAMP_DIALOG_STYLE_OFFSET				:= 0x2C
global SAMP_DIALOG_ID_OFFSET				:= 0x30
global SAMP_DIALOG_TEXT_PTR_OFFSET			:= 0x34
global SAMP_DIALOG_CAPTION_OFFSET			:= 0x40
global SAMP_PLAYER_MAX                      := 1004
global SAMP_KILLSTAT_OFFSET                 := 0x21A0EC
global multVehicleSpeed_tick                := 0
global CheckpointCheck 						:= 0xC7DEEA
global rmaddrs 								:= [0xC7DEC8, 0xC7DECC, 0xC7DED0] 

global cnsl_stdin, cnsl_stdout

getDialogStructPtr() {
	if (!checkHandles()) {
		ErrorLevel := ERROR_INVALID_HANDLE
		return false
	}

	dwPointer := readDWORD(hGTA, dwSAMP + SAMP_DIALOG_STRUCT_PTR)
	if (ErrorLevel) {
		ErrorLevel := ERROR_READ_MEMORY
		return false
	}

	ErrorLevel := ERROR_OK
	return dwPointer
}

gameWaitLogin() {
	loop {
		IfWinNotExist, ahk_exe gta_sa.exe
			return 0
		
		IfWinNotActive, ahk_exe gta_sa.exe
			continue
		
		if !CheckHandles()
			continue
		
		sleep 1000
		getCoordinates(player_x, player_y, player_z)
		if IsPlayerInRangeOfPoint2D(659, -90, player_x, player_z, 50)
			continue
		
		return 1
	}
}

ConnectedToInternet(flag=0x40) { 
	Return DllCall("Wininet.dll\InternetGetConnectedState", "Str", flag,"Int",0) 
}

getCurrentCity() {
	getCoordinates(posX, posY, posZ)
	if (posy > 995)
		return "Интерьер"
	
	loop, parse, _mapcity, `n
	{
		xpos := "", zpos := "", name := "", radius := ""
		loop, parse, A_LoopField, `|
		{
			if A_Index = 1
				xpos := A_LoopField
			
			if A_Index = 2
				zpos := A_LoopField
			
			if A_Index = 3
				name := A_LoopField
			
			if A_Index = 4
				radius := A_LoopField
		}
		
		getCoordinates(player_x, p, player_z)
		if (IsPlayerInRangeOfPoint2D(xpos, zpos, player_x, player_z, radius)) {
			return name
		}
	}
	
	return "Не в городе"
}

cld(text) {
	loop {
		r := cldd(text)
		if !r
		{
			break
		}
	}
	return 0
}

cldd(text) { ; chat log delete
	line_index = -1
	loop, 20
	{
		line_index += 1
		org_f := GetChatLine(line_index, 1, 1)
		line_text := RegExReplace(org_f, "Ui)\{[a-f0-9]{6}\}")
		if line_text contains %text%
		{
			finded = 1
			break
		}
	}
	
	if finded
	{
		fileread, c, % path_chatlog
		StringReplace, c, c, % org_f, % "<  [GH] Строка чата удалена  >", All
		filedelete, % path_chatlog
		fileappend, % c, % path_chatlog
		console.writeln("INFO | CLD finded > " org_f)
		return 1
	}
	
	console.writeln("INFO | CLD not finded! > " org_f)
	return 0
}

class ghtruck {
	dropAll() {
		global
		ghtruck_history := ""
		ghtruck_income := 0
		ghtruck_expense := 0
		return true
	}

	dropHistory() {
		global
		ghtruck_history := ""
		return true
	}
	
	getHistory() {
		global
		return ghtruck_history
	}
	
	writeHistory(money, description) {
		global
		if (money < 0) {
			ghtruck.expense(money)
		}
		else {
			ghtruck.income(money)
			money := "+" money
		}
		
		if ghtruck_history
			ghtruck_history := ghtruck_history "`n" money "Р`t" description
		else
			ghtruck_history := ghtruck_history money "Р`t" description
		
		return true
	}
	
	income(money="") {
		global
		ghtruck_income := ghtruck_income + money
		return ghtruck_income
	}
	
	expense(money="") {
		global
		ghtruck_expense := ghtruck_expense + StrReplace(money, "-")
		return ghtruck_expense
	}
	
	summarize() {
		global
		return ghtruck_income - ghtruck_expense
	}
	
	rent(money) {
		global
		ghtruck.writeHistory(0 - money, "Аренда грузовика")
		return true
	}
	
	loadCargo(money) {
		global
		ghtruck.writeHistory(0 - money, "Загрузка груза")
		return true
	}
	
	unloadCargo(money) {
		global
		ghtruck.writeHistory(money, "Разгрузка груза")
		return true
	}
}

GetFileSizeFromInternet(url, ProxyName = "", ProxyBypass = "")
{
   INTERNET_OPEN_TYPE_DIRECT = 1
   INTERNET_OPEN_TYPE_PROXY = 3
   AccessType := ProxyName ? INTERNET_OPEN_TYPE_DIRECT : INTERNET_OPEN_TYPE_PROXY
   INTERNET_FLAG_RELOAD = 0x80000000
   HTTP_QUERY_CONTENT_LENGTH = 5
   coding := A_IsUnicode ? "W" : "A"
 
   hModule := DllCall("LoadLibrary", Str, "wininet.dll")
   hInternet := DllCall("wininet\InternetOpen" . coding
                  , Str, ""   
                  , UInt, INTERNET_OPEN_TYPE_DIRECT
                  , Str, ""
                  , Str, ""
                  , UInt, 0)
   if !hInternet
   {
      Error := A_LastError
      DllCall("FreeLibrary", UInt, hModule)
      Return "Ошибка " . Error
   }
 
   hFile := DllCall("wininet\InternetOpenUrl" . coding
               , UInt, hInternet
               , Str, url
               , Str, ""
               , UInt, 0
               , UInt, INTERNET_FLAG_RELOAD
               , UInt, 0)
   if !hFile
   {
      Error := A_LastError
      DllCall("wininet\InternetCloseHandle", UInt, hInternet)
      DllCall("FreeLibrary", UInt, hModule)
      Return "Ошибка " . Error
   }
 
   VarSetCapacity(buff, 64)
   VarSetCapacity(bufflen, 2)
   Loop 4
   {
      success := DllCall("wininet\HttpQueryInfo" . coding
                  , UInt, hFile
                  , UInt, HTTP_QUERY_CONTENT_LENGTH
                  , UInt, &buff
                  , UInt, &bufflen
                  , UInt, 0)
      if success
         Break
   }
   Result := success ? StrGet(&buff) : "Невозможно извлечь информацию"
 
   DllCall("wininet\InternetCloseHandle", UInt, hInternet)
   DllCall("wininet\InternetCloseHandle", UInt, hFile)
   DllCall("FreeLibrary", UInt, hModule)
 
   Return Result
}

class console {
	flushBuffer() {
		cnsl_stdout.Read(0)
	}
	
	create() {
		DllCall("AllocConsole")
		cnsl_stdin := FileOpen(DllCall("GetStdHandle", "int", -10, "ptr"), "h `n")
		cnsl_stdout := FileOpen(DllCall("GetStdHandle", "int", -11, "ptr"), "h `n")
	}
	
	getWID() {
		WinGet, winlist, list
		loop, %winlist%
		{
			wid := winlist%A_Index%
			WinGet, ProcessPath, ProcessPath, ahk_id %wid%
			
			if (processPath = A_ScriptFullPath) {
				WinGetClass, processClass, ahk_id %wid%
				if (processClass = "ConsoleWindowClass") {
					cnsl_wid := wid
				}
			}
		}
		
		if (!cnsl_wid) { ; not compiled
			return -1
		} else {
			return cnsl_wid
		}
	}
	
	setTitle(title) {
		wid := console.getWID()
		if (wid = -1)
			return false
		
		WinSetTitle, ahk_id %wid%,, % title
		return true
	}
	
	read() {
		result := RTrim(cnsl_stdin.ReadLine(), "`n")
		console.flushBuffer()
		return result
	}
	
	write(text) {
		result := cnsl_stdout.write(text)
		console.flushBuffer()
		return result
	}
	
	writeln(text) {
		result := cnsl_stdout.WriteLine(text)
		console.flushBuffer()
		
		ifexist, %A_ProgramFiles%\GOS Helper
			fileappend, %text%`n, %A_ProgramFiles%\GOS Helper\log.txt
		
		return result
	}
}

Submit_All(){
	Gui,1:Submit,NoHide
}
Move_Window(){
	PostMessage,0xA1,2
}

Min_Window(){
	Gui,1:Minimize
}

Watch_Hover(){
	Static Index,lctrl,Hover_On
	MouseGetPos,,,,ctrl,2
	if(!Hover_On&&ctrl){
		loop,% Button.Length()
			if(ctrl=Button[A_Index].hwnd)
				Button[A_Index].Draw_Hover(),lctrl:=ctrl,Index:=A_Index,Hover_On:=1,break
	}else if(Hover_On=1)
		if((!ctrl||lctrl!=ctrl)&&Button[Index].isPressed=0)
			Button[Index].Draw_Default(),Hover_On:=0
}

SetTaskbarProgress(pct, state="")
{
    static tbl, s0:=0, sI:=1, sN:=2, sE:=4, sP:=8
    if !tbl 
		tbl := ComObjCreate("{56FDF344-FD6D-11d0-958A-006097C9A090}", "{ea1afb91-9e28-4b86-90e9-9e9f8a5eefaf}")  
    if pct is not number
        state := pct, pct := ""
    else if (pct = 0 && state="")
        state := 0, pct := ""
    if state in 0,I,N,E,P   ; ITaskbarList3::SetProgressState
        DllCall(NumGet(NumGet(tbl+0)+10*A_PtrSize), "ptr", tbl, "ptr", mainwid, "uint", s%state%)
    if pct !=               ; ITaskbarList3::SetProgressValue
        DllCall(NumGet(NumGet(tbl+0)+9*A_PtrSize), "ptr", tbl, "ptr", mainwid, "int64", pct*10, "int64", 1000)
}

Clip_New_Window(){
	if(!Button[A_GuiControl].Draw_Pressed())
		return
	if(X_Position_Edit&&Y_Position_Edit){
		Clipboard:="Main := New Custom_Window( x:= " X_Position_Edit " , y:= " Y_Position_Edit " , w:= " W_Position_Edit " , h:= " H_Position_Edit  " , Name:= """ Name_Edit """ , Options:= """ Options_Edit """ , Title:= """ Title_Edit """ , Background_Bitmap:= " Bitmap_Edit " )`n`nMain.Show_Window()"
	}else if(X_Position_Edit&&!Y_Position_Edit)
		Clipboard:="Main := New Custom_Window( x:= " X_Position_Edit " , y:= """" , w:= " W_Position_Edit " , h:= " H_Position_Edit  " , Name:= """ Name_Edit """ , Options:= """ Options_Edit """ , Title:= """ Title_Edit """ , Background_Bitmap:= " Bitmap_Edit " )`n`nMain.Show_Window()"
	else if(!X_Position_Edit&&Y_Position_Edit)
		Clipboard:="Main := New Custom_Window( x:= """" , y:= " Y_Position_Edit " , w:= " W_Position_Edit " , h:= " H_Position_Edit  " , Name:= """ Name_Edit """ , Options:= """ Options_Edit """ , Title:= """ Title_Edit """ , Background_Bitmap:= " Bitmap_Edit " )`n`nMain.Show_Window()"
	else 
		Clipboard:="Main := New Custom_Window( x:= """" , y:= """" , w:= " W_Position_Edit " , h:= " H_Position_Edit  " , Name:= """ Name_Edit """ , Options:= """ Options_Edit """ , Title:= """ Title_Edit """ , Background_Bitmap:= " Bitmap_Edit " )`n`nMain.Show_Window()"
	SoundBeep,500
	SoundBeep,600
}

Clip_Full_New_script(){
	if(!Button[A_GuiControl].Draw_Pressed())
		return
	temp:=""
	temp.=Set_Partial_Script_Var() "`n`n`n"
	temp.=Set_Custom_Window_Class_Var() "`n`n`n"
	temp.=Set_Gdip_Lite_Var_1() "`n`n`n"
	temp.=Set_Gdip_Lite_Var_2() "`n`n`n"
	Clipboard:=temp
	Sleep,100
	temp:=""
	SoundBeep,500
	SoundBeep,600
}
Clip_Custom_Window_Class(){
	if(!Button[A_GuiControl].Draw_Pressed())
		return
	Clipboard:=Set_Custom_Window_Class_Var() "`n`n`n"
	SoundBeep,500
	SoundBeep,600
}

blockChatInput() {
    if(!checkHandles())
        return false
    
    VarSetCapacity(nop, 2, 0)
    
    dwFunc := dwSAMP + FUNC_SAMP_SENDSAY
    NumPut(0x04C2,nop,0,"Short")
    writeRaw(hGTA, dwFunc, &nop, 2)
    
    dwFunc := dwSAMP + FUNC_SAMP_SENDCMD
    writeRaw(hGTA, dwFunc, &nop, 2)
    
    return true
}

unBlockChatInput() {
    if(!checkHandles())
        return false
    
    VarSetCapacity(nop, 2, 0)
    
    dwFunc := dwSAMP + FUNC_SAMP_SENDSAY
    NumPut(0xA164,nop,0,"Short")
    writeRaw(hGTA, dwFunc, &nop, 2)
    
    dwFunc := dwSAMP + FUNC_SAMP_SENDCMD
    writeRaw(hGTA, dwFunc, &nop, 2)
    
    return true
}
Clip_gdip_lite(){
	if(!Button[A_GuiControl].Draw_Pressed())
		return
	temp:=""
	Temp.=Set_Gdip_Lite_Var_1() "`n`n`n"
	Temp.=Set_Gdip_Lite_Var_2() "`n`n`n"
	Clipboard:=Temp
	Sleep,100
	Temp:=""
	SoundBeep,500
	SoundBeep,600
}
Clip_New_Script_Partial(){
	if(!Button[A_GuiControl].Draw_Pressed())
		return
	Clipboard:=Set_Partial_Script_Var() "`n`n`n"
	SoundBeep,500
	SoundBeep,600
}

class Button_Type1	{
	__New(x,y,w,h,text,FontSize,name,label,Window,Color:="0xFF186498",Set:=0){
		This.X:=X,This.Y:=Y,This.W:=W,This.H:=H,This.FontSize:=FontSize,This.Text:=Text,This.Name:=Name,This.Label:=Label,This.Color:=Color,This.Window:=Window,This.isPressed:=0,This.Set:=Set
		This.Create_Default_Button()
		This.Create_Hover_Button()
		This.Create_Pressed_Button()
		This.Add_Trigger()
		This.Draw_Default()
	}
	Add_Trigger(){
		global
		Gui,% This.Window ":Add",Picture,% "x" This.X " y" This.Y " w" This.W " h" This.H " v" This.Name " g" This.Label " 0xE"
		GuiControlGet,hwnd,% This.Window ":hwnd",% This.Name
		This.Hwnd:=hwnd
	}
	Create_Default_Button(){
		;Bitmap Created Using: HB Bitmap Maker
		pBitmap:=Gdip_CreateBitmap( This.W , This.H ) 
		 G := Gdip_GraphicsFromImage( pBitmap )
		Gdip_SetSmoothingMode( G , 2 )
		Brush := Gdip_BrushCreateSolid( "0xFFFFFFFF" )
		Gdip_FillRectangle( G , Brush , -1 , -1 , This.W+2 , This.H+2 )
		Gdip_DeleteBrush( Brush )
		Brush := Gdip_BrushCreateSolid( "0xFF060B0F" )
		Gdip_FillRoundedRectangle( G , Brush , 2 , 3 , This.W-5 , This.H-7 , 5 )
		Gdip_DeleteBrush( Brush )
		Brush := Gdip_BrushCreateSolid( "0xFF386aff" )
		Gdip_FillRoundedRectangle( G , Brush , 3 , 4 , This.W-7 , This.H-9 , 5 )
		Gdip_DeleteBrush( Brush )
		Brush := Gdip_CreateLineBrushFromRect( 0 , 0 , This.W , This.H-10 , "0xFF386aff" , "0xFF386aff" , 1 , 1 )
		Gdip_FillRoundedRectangle( G , Brush , 4 , 5 , This.W-9 , This.H-11 , 5 )
		Gdip_DeleteBrush( Brush )
		Brush := Gdip_CreateLineBrushFromRect( 0 , 0 , This.W-30 , This.H+21 , "0xFF386aff" , "0xFF386aff" , 1 , 1 )
		Gdip_FillRoundedRectangle( G , Brush , 4 , 7 , This.W-9 , This.H-13 , 5 )
		Gdip_DeleteBrush( Brush )
		Gdip_TextToGraphics( G , This.Text , "s" This.FontSize " Bold Center vcenter caaFFFFFF x0 y1" , "Segoe UI" , This.W , This.H )
		Gdip_DeleteGraphics( G )
		This.Default_Bitmap := Gdip_CreateHBITMAPFromBitmap(pBitmap)
		Gdip_DisposeImage(pBitmap)
	}
	Create_Hover_Button(){
		;Bitmap Created Using: HB Bitmap Maker
		pBitmap:=Gdip_CreateBitmap( This.W , This.H ) 
		 G := Gdip_GraphicsFromImage( pBitmap )
		Gdip_SetSmoothingMode( G , 2 )
		Brush := Gdip_BrushCreateSolid( "0xFFFFFFFF" )
		Gdip_FillRectangle( G , Brush , -1 , -1 , This.W+2 , This.H+2 )
		Gdip_DeleteBrush( Brush )
		Brush := Gdip_BrushCreateSolid( "0xFF060B0F" )
		Gdip_FillRoundedRectangle( G , Brush , 2 , 3 , This.W-5 , This.H-7 , 5 )
		Gdip_DeleteBrush( Brush )
		Brush := Gdip_BrushCreateSolid( "0xFF386aff" )
		Gdip_FillRoundedRectangle( G , Brush , 3 , 4 , This.W-7 , This.H-9 , 5 )
		Gdip_DeleteBrush( Brush )
		Brush := Gdip_CreateLineBrushFromRect( 0 , 0 , This.W , This.H-10 , "0xFF386aff" , "0xFF386aff" , 1 , 1 )
		Gdip_FillRoundedRectangle( G , Brush , 4 , 5 , This.W-9 , This.H-11 , 5 )
		Gdip_DeleteBrush( Brush )
		Brush := Gdip_CreateLineBrushFromRect( 0 , 0 , This.W-30 , This.H+1 , "0xFF386aff" , "0xFF386aff" , 1 , 1 )
		Gdip_FillRoundedRectangle( G , Brush , 4 , 7 , This.W-9 , This.H-13 , 5 )
		Gdip_DeleteBrush( Brush )
		
		;Gdip_TextToGraphics( G , This.Text , "s" This.FontSize " Bold Center vcenter cFFFFFFFF x-1 y2" , "Segoe UI" , This.W , This.H )
		Gdip_TextToGraphics( G , This.Text , "s" This.FontSize " Bold Center vcenter cFFDCDCDC x-1 y1" , "Segoe UI" , This.W , This.H )
		Gdip_TextToGraphics( G , This.Text , "s" This.FontSize " Bold Center vcenter cFFDCDCDC x-1 y0" , "Segoe UI" , This.W , This.H )
		;Gdip_TextToGraphics( G , This.Text , "s" This.FontSize " Bold Center vcenter cFFFFFFFF x0 y0" , "Segoe UI" , This.W , This.H )
		;Gdip_TextToGraphics( G , This.Text , "s" This.FontSize " Bold Center vcenter cFFFFFFFF x1 y2" , "Segoe UI" , This.W , This.H )
		;Gdip_TextToGraphics( G , This.Text , "s" This.FontSize " Bold Center vcenter cFFFFFFFF x1 y1" , "Segoe UI" , This.W , This.H )
		
		Gdip_TextToGraphics( G , This.Text , "s" This.FontSize " Bold Center vcenter caaF0F0F0 x0 y1" , "Segoe UI" , This.W , This.H )
		Gdip_DeleteGraphics( G )
		This.Hover_Bitmap := Gdip_CreateHBITMAPFromBitmap(pBitmap)
		Gdip_DisposeImage(pBitmap)
	}
	Create_Pressed_Button(){
		;Bitmap Created Using: HB Bitmap Maker
		pBitmap:=Gdip_CreateBitmap( This.W , This.H ) 
		 G := Gdip_GraphicsFromImage( pBitmap )
		Gdip_SetSmoothingMode( G , 4 )
		Brush := Gdip_BrushCreateSolid( "0xFF1C2125" )
		Gdip_FillRectangle( G , Brush , -1 , -1 , This.W+2 , This.H+2 )
		Gdip_DeleteBrush( Brush )
		Brush := Gdip_BrushCreateSolid( "0xFF31363B" )
		Gdip_FillRoundedRectangle( G , Brush , 2 , 3 , This.W-5 , This.H-6 , 5 )
		Gdip_DeleteBrush( Brush )
		Brush := Gdip_CreateLineBrushFromRect( 0 , 0 , This.W , This.H , "0xFF151A20" , "0xFF151A20" , 1 , 1 )
		Gdip_FillRoundedRectangle( G , Brush , 2 , 3 , This.W-5 , This.H-8 , 5 )
		Gdip_DeleteBrush( Brush )
		Brush := Gdip_CreateLineBrushFromRect( 0 , 0 , This.W-7 , This.H+10  , "0xFF003366" , "0xFF42474D"  , 1 , 1 )
		Gdip_FillRoundedRectangle( G , Brush , 3 , 4 , This.W-7 , This.H-10 , 5 )
		Gdip_DeleteBrush( Brush )
		Gdip_TextToGraphics( G , This.Text , "s" This.FontSize " Bold Center vcenter caaF0F0F0 x0 y0" , "Segoe UI" , This.W , This.H )
		Gdip_DeleteGraphics( G )
		This.Pressed_Bitmap := Gdip_CreateHBITMAPFromBitmap(pBitmap)
		Gdip_DisposeImage(pBitmap)
	}
	Draw_Default(){
		SetImage(This.Hwnd, This.Default_Bitmap)
	}
	Draw_Hover(){
		SetImage(This.Hwnd, This.Hover_Bitmap)
	}
	Draw_Pressed(){
		SetImage(This.Hwnd, This.Pressed_Bitmap)
		SetTimer,Watch_Hover,Off
		While(GetKeyState("LButton"))
			sleep,10
		SetTimer,Watch_Hover,On
		MouseGetPos,,,,ctrl,2
		if(ctrl!=This.hwnd){
			This.Draw_Default()
			return false
		}else	{
			This.Draw_Hover()
			return true
		}
	}
}

Class Custom_Window	{
	__New(x:="",y:="",w:=300,h:=200,Name:=1,Options:="+AlwaysOnTop -Caption -DPIScale",Title:="",Background_Bitmap:=""){
		This.X:=x
		This.Y:=y
		This.W:=w 
		This.H:=h 
		This.Name:=Name
		This.Title:=Title
		This.Options:=Options
		This.Background_Bitmap:=Background_Bitmap
		This.Create_Window()
	}
	Create_Window(){
		Gui,% This.Name ":New",%  This.Options " +LastFound"
		This.Hwnd:=WinExist()
		if(This.Background_Bitmap)
			This.Draw_Background_Bitmap()
	}
	Draw_Background_Bitmap(){
		This.Bitmap:=Gdip_CreateHBITMAPFromBitmap(This.Background_Bitmap)
		Gdip_DisposeImage(This.Background_Bitmap)
		Gui,% This.Name ":Add",Picture,% "x0 y0 w" This.W " h" This.H " 0xE" 
		GuiControlGet,hwnd,% This.Name ":hwnd",Static1
		This.Background_Hwnd:=hwnd
		SetImage(This.Background_Hwnd,This.Bitmap)
	}
	Show_Window(){
		if(This.X&&This.Y)
			Gui,% This.Name ":Show",% "x" This.X " y" This.Y " w" This.W " h" This.H,% This.Title
		else if(This.X&&!This.Y)
			Gui,% This.Name ":Show",% "x" This.X  " w" This.W " h" This.H,% This.Title
		else if(!This.X&&This.Y)
			Gui,% This.Name ":Show",% "y" This.Y  " w" This.W " h" This.H,% This.Title
		else 
			Gui,% This.Name ":Show",% " w" This.W " h" This.H,% This.Title
	}
}

Custom_Window_Maker_Tool_Background(){
	;Bitmap Created Using: HB Bitmap Maker
	pBitmap:=Gdip_CreateBitmap( 400 , 250 ) 
	 G := Gdip_GraphicsFromImage( pBitmap )
	Gdip_SetSmoothingMode( G , 4 )
	Brush := Gdip_CreateLineBrush( 79 , 39 , 174 , 181 , "0xFF3399FF" , "0xFF000000" , 1 )
	Gdip_FillRectangle( G , Brush , 0 , 0 , 400 , 250 )
	Gdip_DeleteBrush( Brush )
	Brush := Gdip_CreateLineBrush( 43 , -30 , 237 , 269 , "0xFF777777" , "0xFF000000" , 1 )
	Pen := Gdip_CreatePenFromBrush( Brush , 1 )
	Gdip_DeleteBrush( Brush )
	Gdip_DrawRectangle( G , Pen , 0 , 0 , 399 , 249 )
	Gdip_DeletePen( Pen )
	Brush := Gdip_BrushCreateSolid( "0xFF333333" )
	Gdip_FillRectangle( G , Brush , 5 , 30 , 389 , 214 )
	Gdip_DeleteBrush( Brush )
	;move window
	Brush := Gdip_CreateLineBrushFromRect( 7 , 3 , 188 , 23 , "0xFF777777" , "0xFF222222" , 1 , 1 )
	Gdip_FillRoundedRectangle( G , Brush , 46 , 4 , 270 , 22 , 5 )
	Gdip_DeleteBrush( Brush )
	Pen := Gdip_CreatePen( "0xFF333333" , 1 )
	Gdip_DrawRoundedRectangle( G , Pen , 46 , 4 , 270 , 22 , 5 )
	Gdip_DeletePen( Pen )
	Brush := Gdip_BrushCreateSolid( "0xFF000000" )
	Gdip_TextToGraphics( G , "HB Custom Window Maker" , "s12 Center vCenter Bold c" Brush " x85 y2" , "Segoe UI" , 190 , 24 )
	Gdip_DeleteBrush( Brush )
	Brush := Gdip_BrushCreateSolid( "0xFF000000" )
	Gdip_TextToGraphics( G , "HB Custom Window Maker" , "s12 Center vCenter Bold c" Brush " x87 y2" , "Segoe UI" , 190 , 24 )
	Gdip_DeleteBrush( Brush )
	Brush := Gdip_BrushCreateSolid( "0xFF000000" )
	Gdip_TextToGraphics( G , "HB Custom Window Maker" , "s12 Center vCenter Bold c" Brush " x87 y4" , "Segoe UI" , 190 , 24 )
	Gdip_DeleteBrush( Brush )
	Brush := Gdip_BrushCreateSolid( "0xFF000000" )
	Gdip_TextToGraphics( G , "HB Custom Window Maker" , "s12 Center vCenter Bold c" Brush " x85 y4" , "Segoe UI" , 190 , 24 )
	Gdip_DeleteBrush( Brush )
	Brush := Gdip_BrushCreateSolid( "0xFFF0F0F0" )
	Gdip_TextToGraphics( G , "HB Custom Window Maker" , "s12 Center vCenter Bold c" Brush " x86 y3" , "Segoe UI" , 190 , 24 )
	Gdip_DeleteBrush( Brush )
	;close window
	Brush := Gdip_CreateLineBrushFromRect( 380 , 3 , 16 , 17 , "0xFF777777" , "0xFF222222" , 1 , 1 )
	Gdip_FillRectangle( G , Brush , 380 , 5 , 15 , 15 )
	Gdip_DeleteBrush( Brush )
	Brush := Gdip_CreateLineBrush( 388 , 21 , 387 , -7 , "0xFF202020" , "0xFFF0F0F0" , 1 )
	Pen := Gdip_CreatePenFromBrush( Brush , 1 )
	Gdip_DeleteBrush( Brush )
	Gdip_DrawRectangle( G , Pen , 380 , 5 , 15 , 15 )
	Gdip_DeletePen( Pen )
	;min window
	Brush := Gdip_CreateLineBrushFromRect( 380 , 3 , 16 , 17 , "0xFF777777" , "0xFF222222" , 1 , 1 )
	Gdip_FillRectangle( G , Brush , 360 , 5 , 15 , 15 )
	Gdip_DeleteBrush( Brush )
	Brush := Gdip_CreateLineBrush( 388 , 21 , 387 , -7 , "0xFF202020" , "0xFFF0F0F0" , 1 )
	Pen := Gdip_CreatePenFromBrush( Brush , 1 )
	Gdip_DeleteBrush( Brush )
	Gdip_DrawRectangle( G , Pen , 360 , 5 , 15 , 15 )
	Gdip_DeletePen( Pen )
	Brush := Gdip_BrushCreateSolid( "0xFFF0F0F0" )
	Gdip_TextToGraphics( G , "_" , "s16 Center vCenter Bold c" Brush " x343 y-16" , "Segoe UI" , 50 , 50 )
	Gdip_DeleteBrush( Brush )
	Brush := Gdip_BrushCreateSolid( "0xFFF0F0F0" )
	Gdip_TextToGraphics( G , "X" , "s12 Center vCenter c" Brush " x363 y-11" , "Segoe UI" , 50 , 50 )
	Gdip_DeleteBrush( Brush )
	Brush := Gdip_BrushCreateHatch( "0xaa333333" , "0x77000000" , 39 )
	Gdip_FillRectangle( G , Brush , 10 , 35 , 240 , 204 )
	Gdip_DeleteBrush( Brush )
	Pen := Gdip_CreatePen( "0xFF222222" , 1 )
	Gdip_DrawRectangle( G , Pen , 10 , 35 , 241 , 205 )
	Gdip_DeletePen( Pen )
	Brush := Gdip_BrushCreateSolid( "0xFFF0F0F0" )
	Gdip_TextToGraphics( G , "X :" , "s10  vCenter Bold c" Brush " x14 y49" , "Arial" , 50 , 22 )
	Gdip_DeleteBrush( Brush )
	Brush := Gdip_BrushCreateSolid( "0xFFF0F0F0" )
	Gdip_TextToGraphics( G , "Y :" , "s10  vCenter Bold c" Brush " x129 y49" , "Arial" , 50 , 22 )
	Gdip_DeleteBrush( Brush )
	Brush := Gdip_BrushCreateSolid( "0xFFF0F0F0" )
	Gdip_TextToGraphics( G , "W :" , "s10 vCenter Bold c" Brush " x14 y88" , "Arial" , 50 , 22 )
	Gdip_DeleteBrush( Brush )
	Brush := Gdip_BrushCreateSolid( "0xFFF0F0F0" )
	Gdip_TextToGraphics( G , "H :" , "s10  vCenter Bold c" Brush " x129 y88" , "Arial" , 50 , 22 )
	Gdip_DeleteBrush( Brush )
	Brush := Gdip_BrushCreateSolid( "0xFFF0F0F0" )
	Gdip_TextToGraphics( G , "Name :" , "s10 vCenter Bold c" Brush " x14 y124" , "Arial" , 50 , 22 )
	Gdip_DeleteBrush( Brush )
	Brush := Gdip_BrushCreateSolid( "0xFFF0F0F0" )
	Gdip_TextToGraphics( G , "Options :" , "s10 vCenter Bold c" Brush " x14 y154" , "Arial" , 50 , 22 )
	Gdip_DeleteBrush( Brush )
	Brush := Gdip_BrushCreateSolid( "0xFFF0F0F0" )
	Gdip_TextToGraphics( G , "Title :" , "s10 vCenter Bold c" Brush " x14 y185" , "Arial" , 50 , 22 )
	Gdip_DeleteBrush( Brush )
	Brush := Gdip_BrushCreateSolid( "0xFFF0F0F0" )
	Gdip_TextToGraphics( G , "Bitmap :" , "s10 vCenter Bold c" Brush " x14 y216" , "Arial" , 50 , 22 )
	Gdip_DeleteBrush( Brush )
	Brush := Gdip_BrushCreateSolid( "0xFF222222" )
	Gdip_FillRoundedRectangle( G , Brush , 254 , 33 , 137 , 208 , 5 )
	Gdip_DeleteBrush( Brush )
	Brush := Gdip_CreateLineBrushFromRect( 256 , 29 , 136 , 212 , "0xFF666666" , "0xFF000000" , 1 , 1 )
	Pen := Gdip_CreatePenFromBrush( Brush , 1 )
	Gdip_DeleteBrush( Brush )
	Gdip_DrawRoundedRectangle( G , Pen , 255 , 33 , 137 , 208 , 5 )
	Gdip_DeletePen( Pen )
	;x edit
	Brush := Gdip_CreateLineBrushFromRect( 34 , 48 , 79 , 20 , "0xFF3399FF" , "0xFF1E1E1E" , 1 , 1 )
	Gdip_FillRoundedRectangle( G , Brush , 35 , 47 , 80 , 22 , 0 )
	Gdip_DeleteBrush( Brush )
	Brush := Gdip_CreateLineBrushFromRect( 31 , 44 , 84 , 25 , "0xFFF0F0F0" , "0xFF222222" , 1 , 1 )
	Pen := Gdip_CreatePenFromBrush( Brush , 1 )
	Gdip_DeleteBrush( Brush )
	Gdip_DrawRoundedRectangle( G , Pen , 35 , 47 , 80 , 22 , 0 )
	Gdip_DeletePen( Pen )
	;y edit
	Brush := Gdip_CreateLineBrushFromRect( 34 , 48 , 79 , 20 , "0xFF3399FF" , "0xFF1E1E1E" , 1 , 1 )
	Gdip_FillRoundedRectangle( G , Brush , 149 , 47 , 80 , 22 , 0 )
	Gdip_DeleteBrush( Brush )
	Brush := Gdip_CreateLineBrushFromRect( 31 , 44 , 84 , 25 , "0xFFF0F0F0" , "0xFF222222" , 1 , 1 )
	Pen := Gdip_CreatePenFromBrush( Brush , 1 )
	Gdip_DeleteBrush( Brush )
	Gdip_DrawRoundedRectangle( G , Pen , 149 , 47 , 80 , 22 , 0 )
	Gdip_DeletePen( Pen )
	;w edit
	Brush := Gdip_CreateLineBrushFromRect( 34 , 48 , 79 , 20 , "0xFF3399FF" , "0xFF1E1E1E" , 1 , 1 )
	Gdip_FillRoundedRectangle( G , Brush , 35 , 87 , 80 , 22 , 0 )
	Gdip_DeleteBrush( Brush )
	Brush := Gdip_CreateLineBrushFromRect( 34 , 84 , 81 , 24 , "0xFFF0F0F0" , "0xFF222222" , 1 , 1 )
	Pen := Gdip_CreatePenFromBrush( Brush , 1 )
	Gdip_DeleteBrush( Brush )
	Gdip_DrawRoundedRectangle( G , Pen , 35 , 87 , 80 , 22 , 0 )
	Gdip_DeletePen( Pen )
	;h edit
	Brush := Gdip_CreateLineBrushFromRect( 34 , 48 , 79 , 20 , "0xFF3399FF" , "0xFF1E1E1E" , 1 , 1 )
	Gdip_FillRoundedRectangle( G , Brush , 149 , 87 , 80 , 22 , 0 )
	Gdip_DeleteBrush( Brush )
	Brush := Gdip_CreateLineBrushFromRect( 34 , 84 , 81 , 24 , "0xFFF0F0F0" , "0xFF222222" , 1 , 1 )
	Pen := Gdip_CreatePenFromBrush( Brush , 1 )
	Gdip_DeleteBrush( Brush )
	Gdip_DrawRoundedRectangle( G , Pen , 149 , 87 , 80 , 22 , 0 )
	Gdip_DeletePen( Pen )
	;name edit
	Brush := Gdip_CreateLineBrushFromRect( 72 , 121 , 170 , 23 , "0xFF3399FF" , "0xFF1E1E1E" , 1 , 1 )
	Gdip_FillRoundedRectangle( G , Brush , 73 , 123 , 170 , 22 , 0 )
	Gdip_DeleteBrush( Brush )
	;options edit
	Brush := Gdip_CreateLineBrushFromRect( 76 , 148 , 166 , 25 , "0xFF3399FF" , "0xFF1E1E1E" , 1 , 1 )
	Gdip_FillRoundedRectangle( G , Brush , 73 , 153 , 170 , 22 , 0 )
	Gdip_DeleteBrush( Brush )
	;title edit
	Brush := Gdip_CreateLineBrushFromRect( 75 , 182 , 168 , 23 , "0xFF3399FF" , "0xFF1E1E1E" , 1 , 1 )
	Gdip_FillRoundedRectangle( G , Brush , 73 , 183 , 170 , 22 , 0 )
	Gdip_DeleteBrush( Brush )
	;bitmap edit
	Brush := Gdip_CreateLineBrushFromRect( 73 , 213 , 170 , 18 , "0xFF3399FF" , "0xFF1E1E1E" , 1 , 1 )
	Gdip_FillRoundedRectangle( G , Brush , 73 , 213 , 170 , 22 , 0 )
	Gdip_DeleteBrush( Brush )
	Brush := Gdip_CreateLineBrushFromRect( 72 , 120 , 172 , 26 , "0xFFF0F0F0" , "0xFF222222" , 1 , 1 )
	Pen := Gdip_CreatePenFromBrush( Brush , 1 )
	Gdip_DeleteBrush( Brush )
	Gdip_DrawRoundedRectangle( G , Pen , 73 , 123 , 170 , 22 , 0 )
	Gdip_DeletePen( Pen )
	Brush := Gdip_CreateLineBrushFromRect( 75 , 149 , 172 , 26 , "0xFFF0F0F0" , "0xFF222222" , 1 , 1 )
	Pen := Gdip_CreatePenFromBrush( Brush , 1 )
	Gdip_DeleteBrush( Brush )
	Gdip_DrawRoundedRectangle( G , Pen , 73 , 153 , 170 , 22 , 0 )
	Gdip_DeletePen( Pen )
	Brush := Gdip_CreateLineBrushFromRect( 72 , 180 , 167 , 25 , "0xFFF0F0F0" , "0xFF222222" , 1 , 1 )
	Pen := Gdip_CreatePenFromBrush( Brush , 1 )
	Gdip_DeleteBrush( Brush )
	Gdip_DrawRoundedRectangle( G , Pen , 73 , 183 , 170 , 22 , 0 )
	Gdip_DeletePen( Pen )
	Brush := Gdip_CreateLineBrushFromRect( 72 , 212 , 167 , 25 , "0xFFF0F0F0" , "0xFF222222" , 1 , 1 )
	Pen := Gdip_CreatePenFromBrush( Brush , 1 )
	Gdip_DeleteBrush( Brush )
	Gdip_DrawRoundedRectangle( G , Pen , 73 , 213 , 170 , 22 , 0 )
	Gdip_DeletePen( Pen )
	Gdip_DeleteGraphics( G )
	return pBitmap
}

;######################################################################################################################################
;#####################################################   					    #######################################################
;#####################################################  	  Gdip LITE		    #######################################################
;#####################################################  					    #######################################################
;######################################################################################################################################
; Gdip standard library v1.45 by tic (Tariq Porter) 07/09/11
; Modifed by Rseding91 using fincs 64 bit compatible Gdip library 5/1/2013
BitBlt(ddc, dx, dy, dw, dh, sdc, sx, sy, Raster=""){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("gdi32\BitBlt", Ptr, dDC, "int", dx, "int", dy, "int", dw, "int", dh, Ptr, sDC, "int", sx, "int", sy, "uint", Raster ? Raster : 0x00CC0020)
}
Gdip_DrawImage(pGraphics, pBitmap, dx="", dy="", dw="", dh="", sx="", sy="", sw="", sh="", Matrix=1){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	if (Matrix&1 = "")
		ImageAttr := Gdip_SetImageAttributesColorMatrix(Matrix)
	else if (Matrix != 1)
		ImageAttr := Gdip_SetImageAttributesColorMatrix("1|0|0|0|0|0|1|0|0|0|0|0|1|0|0|0|0|0|" Matrix "|0|0|0|0|0|1")
	if(sx = "" && sy = "" && sw = "" && sh = ""){
		if(dx = "" && dy = "" && dw = "" && dh = ""){
			sx := dx := 0, sy := dy := 0
			sw := dw := Gdip_GetImageWidth(pBitmap)
			sh := dh := Gdip_GetImageHeight(pBitmap)
		}else	{
			sx := sy := 0,sw := Gdip_GetImageWidth(pBitmap),sh := Gdip_GetImageHeight(pBitmap)
		}
	}
	E := DllCall("gdiplus\GdipDrawImageRectRect", Ptr, pGraphics, Ptr, pBitmap, "float", dx, "float", dy, "float", dw, "float", dh, "float", sx, "float", sy, "float", sw, "float", sh, "int", 2, Ptr, ImageAttr, Ptr, 0, Ptr, 0)
	if ImageAttr
		Gdip_DisposeImageAttributes(ImageAttr)
	return E
}
Gdip_SetImageAttributesColorMatrix(Matrix){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	VarSetCapacity(ColourMatrix, 100, 0)
	Matrix := RegExReplace(RegExReplace(Matrix, "^[^\d-\.]+([\d\.])", "$1", "", 1), "[^\d-\.]+", "|")
	StringSplit, Matrix, Matrix, |
	Loop, 25
	{
		Matrix := (Matrix%A_Index% != "") ? Matrix%A_Index% : Mod(A_Index-1, 6) ? 0 : 1
		NumPut(Matrix, ColourMatrix, (A_Index-1)*4, "float")
	}
	DllCall("gdiplus\GdipCreateImageAttributes", A_PtrSize ? "UPtr*" : "uint*", ImageAttr)
	DllCall("gdiplus\GdipSetImageAttributesColorMatrix", Ptr, ImageAttr, "int", 1, "int", 1, Ptr, &ColourMatrix, Ptr, 0, "int", 0)
	return ImageAttr
}
Gdip_GetImageWidth(pBitmap){
   DllCall("gdiplus\GdipGetImageWidth", A_PtrSize ? "UPtr" : "UInt", pBitmap, "uint*", Width)
   return Width
}
Gdip_GetImageHeight(pBitmap){
   DllCall("gdiplus\GdipGetImageHeight", A_PtrSize ? "UPtr" : "UInt", pBitmap, "uint*", Height)
   return Height
}
Gdip_DeletePen(pPen){
   return DllCall("gdiplus\GdipDeletePen", A_PtrSize ? "UPtr" : "UInt", pPen)
}
Gdip_DeleteBrush(pBrush){
   return DllCall("gdiplus\GdipDeleteBrush", A_PtrSize ? "UPtr" : "UInt", pBrush)
}
Gdip_DisposeImage(pBitmap){
   return DllCall("gdiplus\GdipDisposeImage", A_PtrSize ? "UPtr" : "UInt", pBitmap)
}
Gdip_DeleteGraphics(pGraphics){
   return DllCall("gdiplus\GdipDeleteGraphics", A_PtrSize ? "UPtr" : "UInt", pGraphics)
}
Gdip_DisposeImageAttributes(ImageAttr){
	return DllCall("gdiplus\GdipDisposeImageAttributes", A_PtrSize ? "UPtr" : "UInt", ImageAttr)
}
Gdip_DeleteFont(hFont){
   return DllCall("gdiplus\GdipDeleteFont", A_PtrSize ? "UPtr" : "UInt", hFont)
}
Gdip_DeleteStringFormat(hFormat){
   return DllCall("gdiplus\GdipDeleteStringFormat", A_PtrSize ? "UPtr" : "UInt", hFormat)
}
Gdip_DeleteFontFamily(hFamily){
   return DllCall("gdiplus\GdipDeleteFontFamily", A_PtrSize ? "UPtr" : "UInt", hFamily)
}
CreateCompatibleDC(hdc=0){
   return DllCall("CreateCompatibleDC", A_PtrSize ? "UPtr" : "UInt", hdc)
}
SelectObject(hdc, hgdiobj){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("SelectObject", Ptr, hdc, Ptr, hgdiobj)
}
DeleteObject(hObject){
   return DllCall("DeleteObject", A_PtrSize ? "UPtr" : "UInt", hObject)
}
GetDC(hwnd=0){
	return DllCall("GetDC", A_PtrSize ? "UPtr" : "UInt", hwnd)
}
GetDCEx(hwnd, flags=0, hrgnClip=0){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
    return DllCall("GetDCEx", Ptr, hwnd, Ptr, hrgnClip, "int", flags)
}
ReleaseDC(hdc, hwnd=0){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("ReleaseDC", Ptr, hwnd, Ptr, hdc)
}
DeleteDC(hdc){
   return DllCall("DeleteDC", A_PtrSize ? "UPtr" : "UInt", hdc)
}
Gdip_SetClipRegion(pGraphics, Region, CombineMode=0){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("gdiplus\GdipSetClipRegion", Ptr, pGraphics, Ptr, Region, "int", CombineMode)
}
CreateDIBSection(w, h, hdc="", bpp=32, ByRef ppvBits=0){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	hdc2 := hdc ? hdc : GetDC()
	VarSetCapacity(bi, 40, 0)
	NumPut(w, bi, 4, "uint"), NumPut(h, bi, 8, "uint"), NumPut(40, bi, 0, "uint"), NumPut(1, bi, 12, "ushort"), NumPut(0, bi, 16, "uInt"), NumPut(bpp, bi, 14, "ushort")
	hbm := DllCall("CreateDIBSection", Ptr, hdc2, Ptr, &bi, "uint", 0, A_PtrSize ? "UPtr*" : "uint*", ppvBits, Ptr, 0, "uint", 0, Ptr)
	if !hdc
		ReleaseDC(hdc2)
	return hbm
}
Gdip_GraphicsFromImage(pBitmap){
	DllCall("gdiplus\GdipGetImageGraphicsContext", A_PtrSize ? "UPtr" : "UInt", pBitmap, A_PtrSize ? "UPtr*" : "UInt*", pGraphics)
	return pGraphics
}
Gdip_GraphicsFromHDC(hdc){
    DllCall("gdiplus\GdipCreateFromHDC", A_PtrSize ? "UPtr" : "UInt", hdc, A_PtrSize ? "UPtr*" : "UInt*", pGraphics)
    return pGraphics
}
Gdip_GetDC(pGraphics){
	DllCall("gdiplus\GdipGetDC", A_PtrSize ? "UPtr" : "UInt", pGraphics, A_PtrSize ? "UPtr*" : "UInt*", hdc)
	return hdc
}
Gdip_Startup(){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	if !DllCall("GetModuleHandle", "str", "gdiplus", Ptr)
		DllCall("LoadLibrary", "str", "gdiplus")
	VarSetCapacity(si, A_PtrSize = 8 ? 24 : 16, 0), si := Chr(1)
	DllCall("gdiplus\GdiplusStartup", A_PtrSize ? "UPtr*" : "uint*", pToken, Ptr, &si, Ptr, 0)
	return pToken
}
GetCoordsSamp(ByRef ResX, ByRef ResY) 
{
    MouseGetPos, PosX, PosY
    PosXProc := PosX * 100 / A_ScreenWidth
    PosYProc := PosY * 100 / A_ScreenHeight
    ResX := PosXProc * 8
    ResY := PosYProc * 6
}
IsPlayerInRangeOfPoint2D(_posX, _posZ, playerX, playerZ, _posRadius)
{
	posX := playerX, posY := playerY, posZ := playerZ
	X := posX - _posX
	Z := posZ - _posZ
	if(((X < _posRadius) && (X > -_posRadius)) && ((Z < _posRadius) && (Z > -_posRadius)))
		return TRUE
	return FALSE
}
Gdip_TextToGraphics(pGraphics, Text, Options, Font="Arial", Width="", Height="", Measure=0){
	IWidth := Width, IHeight:= Height
	RegExMatch(Options, "i)X([\-\d\.]+)(p*)", xpos)
	RegExMatch(Options, "i)Y([\-\d\.]+)(p*)", ypos)
	RegExMatch(Options, "i)W([\-\d\.]+)(p*)", Width)
	RegExMatch(Options, "i)H([\-\d\.]+)(p*)", Height)
	RegExMatch(Options, "i)C(?!(entre|enter))([a-f\d]+)", Colour)
	RegExMatch(Options, "i)Top|Up|Bottom|Down|vCentre|vCenter", vPos)
	RegExMatch(Options, "i)NoWrap", NoWrap)
	RegExMatch(Options, "i)R(\d)", Rendering)
	RegExMatch(Options, "i)S(\d+)(p*)", Size)
	if !Gdip_DeleteBrush(Gdip_CloneBrush(Colour2))
		PassBrush := 1, pBrush := Colour2
	if !(IWidth && IHeight) && (xpos2 || ypos2 || Width2 || Height2 || Size2)
		return -1
	Style := 0, Styles := "Regular|Bold|Italic|BoldItalic|Underline|Strikeout"
	Loop, Parse, Styles, |
	{
		if RegExMatch(Options, "\b" A_loopField)
		Style |= (A_LoopField != "StrikeOut") ? (A_Index-1) : 8
	}
	Align := 0, Alignments := "Near|Left|Centre|Center|Far|Right"
	Loop, Parse, Alignments, |
	{
		if RegExMatch(Options, "\b" A_loopField)
			Align |= A_Index//2.1      ; 0|0|1|1|2|2
	}
	xpos := (xpos1 != "") ? xpos2 ? IWidth*(xpos1/100) : xpos1 : 0
	ypos := (ypos1 != "") ? ypos2 ? IHeight*(ypos1/100) : ypos1 : 0
	Width := Width1 ? Width2 ? IWidth*(Width1/100) : Width1 : IWidth
	Height := Height1 ? Height2 ? IHeight*(Height1/100) : Height1 : IHeight
	if !PassBrush
		Colour := "0x" (Colour2 ? Colour2 : "ff000000")
	Rendering := ((Rendering1 >= 0) && (Rendering1 <= 5)) ? Rendering1 : 4
	Size := (Size1 > 0) ? Size2 ? IHeight*(Size1/100) : Size1 : 12
	hFamily := Gdip_FontFamilyCreate(Font)
	hFont := Gdip_FontCreate(hFamily, Size, Style)
	FormatStyle := NoWrap ? 0x4000 | 0x1000 : 0x4000
	hFormat := Gdip_StringFormatCreate(FormatStyle)
	pBrush := PassBrush ? pBrush : Gdip_BrushCreateSolid(Colour)
	if !(hFamily && hFont && hFormat && pBrush && pGraphics)
		return !pGraphics ? -2 : !hFamily ? -3 : !hFont ? -4 : !hFormat ? -5 : !pBrush ? -6 : 0
	CreateRectF(RC, xpos, ypos, Width, Height)
	Gdip_SetStringFormatAlign(hFormat, Align)
	Gdip_SetTextRenderingHint(pGraphics, Rendering)
	ReturnRC := Gdip_MeasureString(pGraphics, Text, hFont, hFormat, RC)
	if vPos
	{
		StringSplit, ReturnRC, ReturnRC, |
		if (vPos = "vCentre") || (vPos = "vCenter")
			ypos += (Height-ReturnRC4)//2
		else if (vPos = "Top") || (vPos = "Up")
			ypos := 0
		else if (vPos = "Bottom") || (vPos = "Down")
			ypos := Height-ReturnRC4
		CreateRectF(RC, xpos, ypos, Width, ReturnRC4)
		ReturnRC := Gdip_MeasureString(pGraphics, Text, hFont, hFormat, RC)
	}
	if !Measure
		E := Gdip_DrawString(pGraphics, Text, hFont, hFormat, pBrush, RC)
	if !PassBrush
		Gdip_DeleteBrush(pBrush)
	Gdip_DeleteStringFormat(hFormat)   
	Gdip_DeleteFont(hFont)
	Gdip_DeleteFontFamily(hFamily)
	return E ? E : ReturnRC
}
Gdip_DrawString(pGraphics, sString, hFont, hFormat, pBrush, ByRef RectF){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	if (!A_IsUnicode)
	{
		nSize := DllCall("MultiByteToWideChar", "uint", 0, "uint", 0, Ptr, &sString, "int", -1, Ptr, 0, "int", 0)
		VarSetCapacity(wString, nSize*2)
		DllCall("MultiByteToWideChar", "uint", 0, "uint", 0, Ptr, &sString, "int", -1, Ptr, &wString, "int", nSize)
	}
	return DllCall("gdiplus\GdipDrawString", Ptr, pGraphics, Ptr, A_IsUnicode ? &sString : &wString, "int", -1, Ptr, hFont, Ptr, &RectF, Ptr, hFormat, Ptr, pBrush)
}
Gdip_CreateLineBrush(x1, y1, x2, y2, ARGB1, ARGB2, WrapMode=1){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	CreatePointF(PointF1, x1, y1), CreatePointF(PointF2, x2, y2)
	DllCall("gdiplus\GdipCreateLineBrush", Ptr, &PointF1, Ptr, &PointF2, "Uint", ARGB1, "Uint", ARGB2, "int", WrapMode, A_PtrSize ? "UPtr*" : "UInt*", LGpBrush)
	return LGpBrush
}

set_player_armed_weapon_to(weaponid)
{
    c := getPlayerWeaponId()
    WinGet, gtapid, List, ahk_exe gta_sa.exe
    SendMessage, 0x50,, 0x4190419,, ahk_exe gta_sa.exe
    
	Loop {
        ControlSend,, {e down}, ahk_id %gtapid1%
        Sleep, 5
        ControlSend,, {e up}, ahk_id %gtapid1%
		
        if (getPlayerWeaponId() == c || getPlayerWeaponId() == weaponid)
            break
    }
}

Gdip_CreateLineBrushFromRect(x, y, w, h, ARGB1, ARGB2, LinearGradientMode=1, WrapMode=1){
	CreateRectF(RectF, x, y, w, h)
	DllCall("gdiplus\GdipCreateLineBrushFromRect", A_PtrSize ? "UPtr" : "UInt", &RectF, "int", ARGB1, "int", ARGB2, "int", LinearGradientMode, "int", WrapMode, A_PtrSize ? "UPtr*" : "UInt*", LGpBrush)
	return LGpBrush
}
Gdip_CloneBrush(pBrush){
	DllCall("gdiplus\GdipCloneBrush", A_PtrSize ? "UPtr" : "UInt", pBrush, A_PtrSize ? "UPtr*" : "UInt*", pBrushClone)
	return pBrushClone
}
Gdip_FontFamilyCreate(Font){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	if (!A_IsUnicode)
	{
		nSize := DllCall("MultiByteToWideChar", "uint", 0, "uint", 0, Ptr, &Font, "int", -1, "uint", 0, "int", 0)
		VarSetCapacity(wFont, nSize*2)
		DllCall("MultiByteToWideChar", "uint", 0, "uint", 0, Ptr, &Font, "int", -1, Ptr, &wFont, "int", nSize)
	}
	DllCall("gdiplus\GdipCreateFontFamilyFromName", Ptr, A_IsUnicode ? &Font : &wFont, "uint", 0, A_PtrSize ? "UPtr*" : "UInt*", hFamily)
	return hFamily
}
Gdip_SetStringFormatAlign(hFormat, Align){
   return DllCall("gdiplus\GdipSetStringFormatAlign", A_PtrSize ? "UPtr" : "UInt", hFormat, "int", Align)
}
Gdip_StringFormatCreate(Format=0, Lang=0){
   DllCall("gdiplus\GdipCreateStringFormat", "int", Format, "int", Lang, A_PtrSize ? "UPtr*" : "UInt*", hFormat)
   return hFormat
}
Gdip_FontCreate(hFamily, Size, Style=0){
   DllCall("gdiplus\GdipCreateFont", A_PtrSize ? "UPtr" : "UInt", hFamily, "float", Size, "int", Style, "int", 0, A_PtrSize ? "UPtr*" : "UInt*", hFont)
   return hFont
}
Gdip_CreatePen(ARGB, w){
   DllCall("gdiplus\GdipCreatePen1", "UInt", ARGB, "float", w, "int", 2, A_PtrSize ? "UPtr*" : "UInt*", pPen)
   return pPen
}
Gdip_CreatePenFromBrush(pBrush, w){
	DllCall("gdiplus\GdipCreatePen2", A_PtrSize ? "UPtr" : "UInt", pBrush, "float", w, "int", 2, A_PtrSize ? "UPtr*" : "UInt*", pPen)
	return pPen
}
Gdip_BrushCreateSolid(ARGB=0xff000000){
	DllCall("gdiplus\GdipCreateSolidFill", "UInt", ARGB, A_PtrSize ? "UPtr*" : "UInt*", pBrush)
	return pBrush
}
Gdip_BrushCreateHatch(ARGBfront, ARGBback, HatchStyle=0){
	DllCall("gdiplus\GdipCreateHatchBrush", "int", HatchStyle, "UInt", ARGBfront, "UInt", ARGBback, A_PtrSize ? "UPtr*" : "UInt*", pBrush)
	return pBrush
}
CreateRectF(ByRef RectF, x, y, w, h){
   VarSetCapacity(RectF, 16)
   NumPut(x, RectF, 0, "float"), NumPut(y, RectF, 4, "float"), NumPut(w, RectF, 8, "float"), NumPut(h, RectF, 12, "float")
}
Gdip_SetTextRenderingHint(pGraphics, RenderingHint){
	return DllCall("gdiplus\GdipSetTextRenderingHint", A_PtrSize ? "UPtr" : "UInt", pGraphics, "int", RenderingHint)
}
Gdip_MeasureString(pGraphics, sString, hFont, hFormat, ByRef RectF){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	VarSetCapacity(RC, 16)
	if !A_IsUnicode
	{
		nSize := DllCall("MultiByteToWideChar", "uint", 0, "uint", 0, Ptr, &sString, "int", -1, "uint", 0, "int", 0)
		VarSetCapacity(wString, nSize*2)   
		DllCall("MultiByteToWideChar", "uint", 0, "uint", 0, Ptr, &sString, "int", -1, Ptr, &wString, "int", nSize)
	}
	DllCall("gdiplus\GdipMeasureString", Ptr, pGraphics, Ptr, A_IsUnicode ? &sString : &wString, "int", -1, Ptr, hFont, Ptr, &RectF, Ptr, hFormat, Ptr, &RC, "uint*", Chars, "uint*", Lines)
	return &RC ? NumGet(RC, 0, "float") "|" NumGet(RC, 4, "float") "|" NumGet(RC, 8, "float") "|" NumGet(RC, 12, "float") "|" Chars "|" Lines : 0
}
CreateRect(ByRef Rect, x, y, w, h){
	VarSetCapacity(Rect, 16)
	NumPut(x, Rect, 0, "uint"), NumPut(y, Rect, 4, "uint"), NumPut(w, Rect, 8, "uint"), NumPut(h, Rect, 12, "uint")
}
CreateSizeF(ByRef SizeF, w, h){
   VarSetCapacity(SizeF, 8)
   NumPut(w, SizeF, 0, "float"), NumPut(h, SizeF, 4, "float")     
}
CreatePointF(ByRef PointF, x, y){
   VarSetCapacity(PointF, 8)
   NumPut(x, PointF, 0, "float"), NumPut(y, PointF, 4, "float")     
}
Gdip_DrawArc(pGraphics, pPen, x, y, w, h, StartAngle, SweepAngle){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("gdiplus\GdipDrawArc", Ptr, pGraphics, Ptr, pPen, "float", x, "float", y, "float", w, "float", h, "float", StartAngle, "float", SweepAngle)
}
Gdip_DrawPie(pGraphics, pPen, x, y, w, h, StartAngle, SweepAngle){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("gdiplus\GdipDrawPie", Ptr, pGraphics, Ptr, pPen, "float", x, "float", y, "float", w, "float", h, "float", StartAngle, "float", SweepAngle)
}
Gdip_DrawLine(pGraphics, pPen, x1, y1, x2, y2){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("gdiplus\GdipDrawLine", Ptr, pGraphics, Ptr, pPen, "float", x1, "float", y1, "float", x2, "float", y2)
}
Gdip_DrawLines(pGraphics, pPen, Points){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	StringSplit, Points, Points, |
	VarSetCapacity(PointF, 8*Points0)   
	Loop, %Points0%
	{
		StringSplit, Coord, Points%A_Index%, `,
		NumPut(Coord1, PointF, 8*(A_Index-1), "float"), NumPut(Coord2, PointF, (8*(A_Index-1))+4, "float")
	}
	return DllCall("gdiplus\GdipDrawLines", Ptr, pGraphics, Ptr, pPen, Ptr, &PointF, "int", Points0)
}
Gdip_FillRectangle(pGraphics, pBrush, x, y, w, h){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("gdiplus\GdipFillRectangle", Ptr, pGraphics, Ptr, pBrush, "float", x, "float", y, "float", w, "float", h)
}
Gdip_FillRoundedRectangle(pGraphics, pBrush, x, y, w, h, r){
	Region := Gdip_GetClipRegion(pGraphics)
	Gdip_SetClipRect(pGraphics, x-r, y-r, 2*r, 2*r, 4)
	Gdip_SetClipRect(pGraphics, x+w-r, y-r, 2*r, 2*r, 4)
	Gdip_SetClipRect(pGraphics, x-r, y+h-r, 2*r, 2*r, 4)
	Gdip_SetClipRect(pGraphics, x+w-r, y+h-r, 2*r, 2*r, 4)
	E := Gdip_FillRectangle(pGraphics, pBrush, x, y, w, h)
	Gdip_SetClipRegion(pGraphics, Region, 0)
	Gdip_SetClipRect(pGraphics, x-(2*r), y+r, w+(4*r), h-(2*r), 4)
	Gdip_SetClipRect(pGraphics, x+r, y-(2*r), w-(2*r), h+(4*r), 4)
	Gdip_FillEllipse(pGraphics, pBrush, x, y, 2*r, 2*r)
	Gdip_FillEllipse(pGraphics, pBrush, x+w-(2*r), y, 2*r, 2*r)
	Gdip_FillEllipse(pGraphics, pBrush, x, y+h-(2*r), 2*r, 2*r)
	Gdip_FillEllipse(pGraphics, pBrush, x+w-(2*r), y+h-(2*r), 2*r, 2*r)
	Gdip_SetClipRegion(pGraphics, Region, 0)
	Gdip_DeleteRegion(Region)
	return E
}
Gdip_GetClipRegion(pGraphics){
	Region := Gdip_CreateRegion()
	DllCall("gdiplus\GdipGetClip", A_PtrSize ? "UPtr" : "UInt", pGraphics, "UInt*", Region)
	return Region
}
Gdip_SetClipRect(pGraphics, x, y, w, h, CombineMode=0){
   return DllCall("gdiplus\GdipSetClipRect",  A_PtrSize ? "UPtr" : "UInt", pGraphics, "float", x, "float", y, "float", w, "float", h, "int", CombineMode)
}
Gdip_SetClipPath(pGraphics, Path, CombineMode=0){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("gdiplus\GdipSetClipPath", Ptr, pGraphics, Ptr, Path, "int", CombineMode)
}
Gdip_ResetClip(pGraphics){
   return DllCall("gdiplus\GdipResetClip", A_PtrSize ? "UPtr" : "UInt", pGraphics)
}
Gdip_FillEllipse(pGraphics, pBrush, x, y, w, h){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("gdiplus\GdipFillEllipse", Ptr, pGraphics, Ptr, pBrush, "float", x, "float", y, "float", w, "float", h)
}
Gdip_FillRegion(pGraphics, pBrush, Region){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("gdiplus\GdipFillRegion", Ptr, pGraphics, Ptr, pBrush, Ptr, Region)
}
Gdip_FillPath(pGraphics, pBrush, Path){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("gdiplus\GdipFillPath", Ptr, pGraphics, Ptr, pBrush, Ptr, Path)
}
Gdip_CreateRegion(){
	DllCall("gdiplus\GdipCreateRegion", "UInt*", Region)
	return Region
}
Gdip_DeleteRegion(Region){
	return DllCall("gdiplus\GdipDeleteRegion", A_PtrSize ? "UPtr" : "UInt", Region)
}
Gdip_CreateBitmap(Width, Height, Format=0x26200A){
    DllCall("gdiplus\GdipCreateBitmapFromScan0", "int", Width, "int", Height, "int", 0, "int", Format, A_PtrSize ? "UPtr" : "UInt", 0, A_PtrSize ? "UPtr*" : "uint*", pBitmap)
    Return pBitmap
}
Gdip_SetSmoothingMode(pGraphics, SmoothingMode){
   return DllCall("gdiplus\GdipSetSmoothingMode", A_PtrSize ? "UPtr" : "UInt", pGraphics, "int", SmoothingMode)
}
Gdip_DrawRectangle(pGraphics, pPen, x, y, w, h){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("gdiplus\GdipDrawRectangle", Ptr, pGraphics, Ptr, pPen, "float", x, "float", y, "float", w, "float", h)
}
Gdip_DrawRoundedRectangle(pGraphics, pPen, x, y, w, h, r){
	Gdip_SetClipRect(pGraphics, x-r, y-r, 2*r, 2*r, 4)
	Gdip_SetClipRect(pGraphics, x+w-r, y-r, 2*r, 2*r, 4)
	Gdip_SetClipRect(pGraphics, x-r, y+h-r, 2*r, 2*r, 4)
	Gdip_SetClipRect(pGraphics, x+w-r, y+h-r, 2*r, 2*r, 4)
	E := Gdip_DrawRectangle(pGraphics, pPen, x, y, w, h)
	Gdip_ResetClip(pGraphics)
	Gdip_SetClipRect(pGraphics, x-(2*r), y+r, w+(4*r), h-(2*r), 4)
	Gdip_SetClipRect(pGraphics, x+r, y-(2*r), w-(2*r), h+(4*r), 4)
	Gdip_DrawEllipse(pGraphics, pPen, x, y, 2*r, 2*r)
	Gdip_DrawEllipse(pGraphics, pPen, x+w-(2*r), y, 2*r, 2*r)
	Gdip_DrawEllipse(pGraphics, pPen, x, y+h-(2*r), 2*r, 2*r)
	Gdip_DrawEllipse(pGraphics, pPen, x+w-(2*r), y+h-(2*r), 2*r, 2*r)
	Gdip_ResetClip(pGraphics)
	return E
}
Gdip_DrawEllipse(pGraphics, pPen, x, y, w, h){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("gdiplus\GdipDrawEllipse", Ptr, pGraphics, Ptr, pPen, "float", x, "float", y, "float", w, "float", h)
}
Gdip_CreateHBITMAPFromBitmap(pBitmap, Background=0xffffffff){
	DllCall("gdiplus\GdipCreateHBITMAPFromBitmap", A_PtrSize ? "UPtr" : "UInt", pBitmap, A_PtrSize ? "UPtr*" : "uint*", hbm, "int", Background)
	return hbm
}
SetImage(hwnd, hBitmap){
	SendMessage, 0x172, 0x0, hBitmap,, ahk_id %hwnd%
	E := ErrorLevel
	DeleteObject(E)
	return E
}

Set_Gdip_Lite_Var_1(){
		Gdip_LITE_Part1 =
	(% ` Join`r`n
;######################################################################################################################################
;#####################################################   					    #######################################################
;#####################################################  	  Gdip LITE		    #######################################################
;#####################################################  					    #######################################################
;######################################################################################################################################
; Gdip standard library v1.45 by tic (Tariq Porter) 07/09/11
; Modifed by Rseding91 using fincs 64 bit compatible Gdip library 5/1/2013
BitBlt(ddc, dx, dy, dw, dh, sdc, sx, sy, Raster=""){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("gdi32\BitBlt", Ptr, dDC, "int", dx, "int", dy, "int", dw, "int", dh, Ptr, sDC, "int", sx, "int", sy, "uint", Raster ? Raster : 0x00CC0020)
}
Gdip_DrawImage(pGraphics, pBitmap, dx="", dy="", dw="", dh="", sx="", sy="", sw="", sh="", Matrix=1){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	if (Matrix&1 = "")
		ImageAttr := Gdip_SetImageAttributesColorMatrix(Matrix)
	else if (Matrix != 1)
		ImageAttr := Gdip_SetImageAttributesColorMatrix("1|0|0|0|0|0|1|0|0|0|0|0|1|0|0|0|0|0|" Matrix "|0|0|0|0|0|1")
	if(sx = "" && sy = "" && sw = "" && sh = ""){
		if(dx = "" && dy = "" && dw = "" && dh = ""){
			sx := dx := 0, sy := dy := 0
			sw := dw := Gdip_GetImageWidth(pBitmap)
			sh := dh := Gdip_GetImageHeight(pBitmap)
		}else	{
			sx := sy := 0,sw := Gdip_GetImageWidth(pBitmap),sh := Gdip_GetImageHeight(pBitmap)
		}
	}
	E := DllCall("gdiplus\GdipDrawImageRectRect", Ptr, pGraphics, Ptr, pBitmap, "float", dx, "float", dy, "float", dw, "float", dh, "float", sx, "float", sy, "float", sw, "float", sh, "int", 2, Ptr, ImageAttr, Ptr, 0, Ptr, 0)
	if ImageAttr
		Gdip_DisposeImageAttributes(ImageAttr)
	return E
}
Gdip_SetImageAttributesColorMatrix(Matrix){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	VarSetCapacity(ColourMatrix, 100, 0)
	Matrix := RegExReplace(RegExReplace(Matrix, "^[^\d-\.]+([\d\.])", "$1", "", 1), "[^\d-\.]+", "|")
	StringSplit, Matrix, Matrix, |
	Loop, 25
	{
		Matrix := (Matrix%A_Index% != "") ? Matrix%A_Index% : Mod(A_Index-1, 6) ? 0 : 1
		NumPut(Matrix, ColourMatrix, (A_Index-1)*4, "float")
	}
	DllCall("gdiplus\GdipCreateImageAttributes", A_PtrSize ? "UPtr*" : "uint*", ImageAttr)
	DllCall("gdiplus\GdipSetImageAttributesColorMatrix", Ptr, ImageAttr, "int", 1, "int", 1, Ptr, &ColourMatrix, Ptr, 0, "int", 0)
	return ImageAttr
}
Gdip_GetImageWidth(pBitmap){
   DllCall("gdiplus\GdipGetImageWidth", A_PtrSize ? "UPtr" : "UInt", pBitmap, "uint*", Width)
   return Width
}
Gdip_GetImageHeight(pBitmap){
   DllCall("gdiplus\GdipGetImageHeight", A_PtrSize ? "UPtr" : "UInt", pBitmap, "uint*", Height)
   return Height
}
Gdip_DeletePen(pPen){
   return DllCall("gdiplus\GdipDeletePen", A_PtrSize ? "UPtr" : "UInt", pPen)
}
Gdip_DeleteBrush(pBrush){
   return DllCall("gdiplus\GdipDeleteBrush", A_PtrSize ? "UPtr" : "UInt", pBrush)
}
Gdip_DisposeImage(pBitmap){
   return DllCall("gdiplus\GdipDisposeImage", A_PtrSize ? "UPtr" : "UInt", pBitmap)
}
Gdip_DeleteGraphics(pGraphics){
   return DllCall("gdiplus\GdipDeleteGraphics", A_PtrSize ? "UPtr" : "UInt", pGraphics)
}
Gdip_DisposeImageAttributes(ImageAttr){
	return DllCall("gdiplus\GdipDisposeImageAttributes", A_PtrSize ? "UPtr" : "UInt", ImageAttr)
}
Gdip_DeleteFont(hFont){
   return DllCall("gdiplus\GdipDeleteFont", A_PtrSize ? "UPtr" : "UInt", hFont)
}
Gdip_DeleteStringFormat(hFormat){
   return DllCall("gdiplus\GdipDeleteStringFormat", A_PtrSize ? "UPtr" : "UInt", hFormat)
}
Gdip_DeleteFontFamily(hFamily){
   return DllCall("gdiplus\GdipDeleteFontFamily", A_PtrSize ? "UPtr" : "UInt", hFamily)
}
CreateCompatibleDC(hdc=0){
   return DllCall("CreateCompatibleDC", A_PtrSize ? "UPtr" : "UInt", hdc)
}
SelectObject(hdc, hgdiobj){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("SelectObject", Ptr, hdc, Ptr, hgdiobj)
}
DeleteObject(hObject){
   return DllCall("DeleteObject", A_PtrSize ? "UPtr" : "UInt", hObject)
}
GetDC(hwnd=0){
	return DllCall("GetDC", A_PtrSize ? "UPtr" : "UInt", hwnd)
}
GetDCEx(hwnd, flags=0, hrgnClip=0){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
    return DllCall("GetDCEx", Ptr, hwnd, Ptr, hrgnClip, "int", flags)
}
ReleaseDC(hdc, hwnd=0){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("ReleaseDC", Ptr, hwnd, Ptr, hdc)
}
DeleteDC(hdc){
   return DllCall("DeleteDC", A_PtrSize ? "UPtr" : "UInt", hdc)
}
Gdip_SetClipRegion(pGraphics, Region, CombineMode=0){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("gdiplus\GdipSetClipRegion", Ptr, pGraphics, Ptr, Region, "int", CombineMode)
}
CreateDIBSection(w, h, hdc="", bpp=32, ByRef ppvBits=0){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	hdc2 := hdc ? hdc : GetDC()
	VarSetCapacity(bi, 40, 0)
	NumPut(w, bi, 4, "uint"), NumPut(h, bi, 8, "uint"), NumPut(40, bi, 0, "uint"), NumPut(1, bi, 12, "ushort"), NumPut(0, bi, 16, "uInt"), NumPut(bpp, bi, 14, "ushort")
	hbm := DllCall("CreateDIBSection", Ptr, hdc2, Ptr, &bi, "uint", 0, A_PtrSize ? "UPtr*" : "uint*", ppvBits, Ptr, 0, "uint", 0, Ptr)
	if !hdc
		ReleaseDC(hdc2)
	return hbm
}
Gdip_GraphicsFromImage(pBitmap){
	DllCall("gdiplus\GdipGetImageGraphicsContext", A_PtrSize ? "UPtr" : "UInt", pBitmap, A_PtrSize ? "UPtr*" : "UInt*", pGraphics)
	return pGraphics
}
Gdip_GraphicsFromHDC(hdc){
    DllCall("gdiplus\GdipCreateFromHDC", A_PtrSize ? "UPtr" : "UInt", hdc, A_PtrSize ? "UPtr*" : "UInt*", pGraphics)
    return pGraphics
}
Gdip_GetDC(pGraphics){
	DllCall("gdiplus\GdipGetDC", A_PtrSize ? "UPtr" : "UInt", pGraphics, A_PtrSize ? "UPtr*" : "UInt*", hdc)
	return hdc
}
	)
	return Gdip_LITE_Part1
}
Set_Gdip_Lite_Var_2(){
	Gdip_LITE_Part2 =
	(% ` Join`r`n
Gdip_Startup(){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	if !DllCall("GetModuleHandle", "str", "gdiplus", Ptr)
		DllCall("LoadLibrary", "str", "gdiplus")
	VarSetCapacity(si, A_PtrSize = 8 ? 24 : 16, 0), si := Chr(1)
	DllCall("gdiplus\GdiplusStartup", A_PtrSize ? "UPtr*" : "uint*", pToken, Ptr, &si, Ptr, 0)
	return pToken
}
Gdip_TextToGraphics(pGraphics, Text, Options, Font="Arial", Width="", Height="", Measure=0){
	IWidth := Width, IHeight:= Height
	RegExMatch(Options, "i)X([\-\d\.]+)(p*)", xpos)
	RegExMatch(Options, "i)Y([\-\d\.]+)(p*)", ypos)
	RegExMatch(Options, "i)W([\-\d\.]+)(p*)", Width)
	RegExMatch(Options, "i)H([\-\d\.]+)(p*)", Height)
	RegExMatch(Options, "i)C(?!(entre|enter))([a-f\d]+)", Colour)
	RegExMatch(Options, "i)Top|Up|Bottom|Down|vCentre|vCenter", vPos)
	RegExMatch(Options, "i)NoWrap", NoWrap)
	RegExMatch(Options, "i)R(\d)", Rendering)
	RegExMatch(Options, "i)S(\d+)(p*)", Size)
	if !Gdip_DeleteBrush(Gdip_CloneBrush(Colour2))
		PassBrush := 1, pBrush := Colour2
	if !(IWidth && IHeight) && (xpos2 || ypos2 || Width2 || Height2 || Size2)
		return -1
	Style := 0, Styles := "Regular|Bold|Italic|BoldItalic|Underline|Strikeout"
	Loop, Parse, Styles, |
	{
		if RegExMatch(Options, "\b" A_loopField)
		Style |= (A_LoopField != "StrikeOut") ? (A_Index-1) : 8
	}
	Align := 0, Alignments := "Near|Left|Centre|Center|Far|Right"
	Loop, Parse, Alignments, |
	{
		if RegExMatch(Options, "\b" A_loopField)
			Align |= A_Index//2.1      ; 0|0|1|1|2|2
	}
	xpos := (xpos1 != "") ? xpos2 ? IWidth*(xpos1/100) : xpos1 : 0
	ypos := (ypos1 != "") ? ypos2 ? IHeight*(ypos1/100) : ypos1 : 0
	Width := Width1 ? Width2 ? IWidth*(Width1/100) : Width1 : IWidth
	Height := Height1 ? Height2 ? IHeight*(Height1/100) : Height1 : IHeight
	if !PassBrush
		Colour := "0x" (Colour2 ? Colour2 : "ff000000")
	Rendering := ((Rendering1 >= 0) && (Rendering1 <= 5)) ? Rendering1 : 4
	Size := (Size1 > 0) ? Size2 ? IHeight*(Size1/100) : Size1 : 12
	hFamily := Gdip_FontFamilyCreate(Font)
	hFont := Gdip_FontCreate(hFamily, Size, Style)
	FormatStyle := NoWrap ? 0x4000 | 0x1000 : 0x4000
	hFormat := Gdip_StringFormatCreate(FormatStyle)
	pBrush := PassBrush ? pBrush : Gdip_BrushCreateSolid(Colour)
	if !(hFamily && hFont && hFormat && pBrush && pGraphics)
		return !pGraphics ? -2 : !hFamily ? -3 : !hFont ? -4 : !hFormat ? -5 : !pBrush ? -6 : 0
	CreateRectF(RC, xpos, ypos, Width, Height)
	Gdip_SetStringFormatAlign(hFormat, Align)
	Gdip_SetTextRenderingHint(pGraphics, Rendering)
	ReturnRC := Gdip_MeasureString(pGraphics, Text, hFont, hFormat, RC)
	if vPos
	{
		StringSplit, ReturnRC, ReturnRC, |
		if (vPos = "vCentre") || (vPos = "vCenter")
			ypos += (Height-ReturnRC4)//2
		else if (vPos = "Top") || (vPos = "Up")
			ypos := 0
		else if (vPos = "Bottom") || (vPos = "Down")
			ypos := Height-ReturnRC4
		CreateRectF(RC, xpos, ypos, Width, ReturnRC4)
		ReturnRC := Gdip_MeasureString(pGraphics, Text, hFont, hFormat, RC)
	}
	if !Measure
		E := Gdip_DrawString(pGraphics, Text, hFont, hFormat, pBrush, RC)
	if !PassBrush
		Gdip_DeleteBrush(pBrush)
	Gdip_DeleteStringFormat(hFormat)   
	Gdip_DeleteFont(hFont)
	Gdip_DeleteFontFamily(hFamily)
	return E ? E : ReturnRC
}
Gdip_DrawString(pGraphics, sString, hFont, hFormat, pBrush, ByRef RectF){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	if (!A_IsUnicode)
	{
		nSize := DllCall("MultiByteToWideChar", "uint", 0, "uint", 0, Ptr, &sString, "int", -1, Ptr, 0, "int", 0)
		VarSetCapacity(wString, nSize*2)
		DllCall("MultiByteToWideChar", "uint", 0, "uint", 0, Ptr, &sString, "int", -1, Ptr, &wString, "int", nSize)
	}
	return DllCall("gdiplus\GdipDrawString", Ptr, pGraphics, Ptr, A_IsUnicode ? &sString : &wString, "int", -1, Ptr, hFont, Ptr, &RectF, Ptr, hFormat, Ptr, pBrush)
}
Gdip_CreateLineBrush(x1, y1, x2, y2, ARGB1, ARGB2, WrapMode=1){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	CreatePointF(PointF1, x1, y1), CreatePointF(PointF2, x2, y2)
	DllCall("gdiplus\GdipCreateLineBrush", Ptr, &PointF1, Ptr, &PointF2, "Uint", ARGB1, "Uint", ARGB2, "int", WrapMode, A_PtrSize ? "UPtr*" : "UInt*", LGpBrush)
	return LGpBrush
}
Gdip_CreateLineBrushFromRect(x, y, w, h, ARGB1, ARGB2, LinearGradientMode=1, WrapMode=1){
	CreateRectF(RectF, x, y, w, h)
	DllCall("gdiplus\GdipCreateLineBrushFromRect", A_PtrSize ? "UPtr" : "UInt", &RectF, "int", ARGB1, "int", ARGB2, "int", LinearGradientMode, "int", WrapMode, A_PtrSize ? "UPtr*" : "UInt*", LGpBrush)
	return LGpBrush
}
Gdip_CloneBrush(pBrush){
	DllCall("gdiplus\GdipCloneBrush", A_PtrSize ? "UPtr" : "UInt", pBrush, A_PtrSize ? "UPtr*" : "UInt*", pBrushClone)
	return pBrushClone
}
Gdip_FontFamilyCreate(Font){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	if (!A_IsUnicode)
	{
		nSize := DllCall("MultiByteToWideChar", "uint", 0, "uint", 0, Ptr, &Font, "int", -1, "uint", 0, "int", 0)
		VarSetCapacity(wFont, nSize*2)
		DllCall("MultiByteToWideChar", "uint", 0, "uint", 0, Ptr, &Font, "int", -1, Ptr, &wFont, "int", nSize)
	}
	DllCall("gdiplus\GdipCreateFontFamilyFromName", Ptr, A_IsUnicode ? &Font : &wFont, "uint", 0, A_PtrSize ? "UPtr*" : "UInt*", hFamily)
	return hFamily
}
Gdip_SetStringFormatAlign(hFormat, Align){
   return DllCall("gdiplus\GdipSetStringFormatAlign", A_PtrSize ? "UPtr" : "UInt", hFormat, "int", Align)
}
Gdip_StringFormatCreate(Format=0, Lang=0){
   DllCall("gdiplus\GdipCreateStringFormat", "int", Format, "int", Lang, A_PtrSize ? "UPtr*" : "UInt*", hFormat)
   return hFormat
}
Gdip_FontCreate(hFamily, Size, Style=0){
   DllCall("gdiplus\GdipCreateFont", A_PtrSize ? "UPtr" : "UInt", hFamily, "float", Size, "int", Style, "int", 0, A_PtrSize ? "UPtr*" : "UInt*", hFont)
   return hFont
}
Gdip_CreatePen(ARGB, w){
   DllCall("gdiplus\GdipCreatePen1", "UInt", ARGB, "float", w, "int", 2, A_PtrSize ? "UPtr*" : "UInt*", pPen)
   return pPen
}
Gdip_CreatePenFromBrush(pBrush, w){
	DllCall("gdiplus\GdipCreatePen2", A_PtrSize ? "UPtr" : "UInt", pBrush, "float", w, "int", 2, A_PtrSize ? "UPtr*" : "UInt*", pPen)
	return pPen
}
Gdip_BrushCreateSolid(ARGB=0xff000000){
	DllCall("gdiplus\GdipCreateSolidFill", "UInt", ARGB, A_PtrSize ? "UPtr*" : "UInt*", pBrush)
	return pBrush
}
Gdip_BrushCreateHatch(ARGBfront, ARGBback, HatchStyle=0){
	DllCall("gdiplus\GdipCreateHatchBrush", "int", HatchStyle, "UInt", ARGBfront, "UInt", ARGBback, A_PtrSize ? "UPtr*" : "UInt*", pBrush)
	return pBrush
}
CreateRectF(ByRef RectF, x, y, w, h){
   VarSetCapacity(RectF, 16)
   NumPut(x, RectF, 0, "float"), NumPut(y, RectF, 4, "float"), NumPut(w, RectF, 8, "float"), NumPut(h, RectF, 12, "float")
}
Gdip_SetTextRenderingHint(pGraphics, RenderingHint){
	return DllCall("gdiplus\GdipSetTextRenderingHint", A_PtrSize ? "UPtr" : "UInt", pGraphics, "int", RenderingHint)
}
Gdip_MeasureString(pGraphics, sString, hFont, hFormat, ByRef RectF){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	VarSetCapacity(RC, 16)
	if !A_IsUnicode
	{
		nSize := DllCall("MultiByteToWideChar", "uint", 0, "uint", 0, Ptr, &sString, "int", -1, "uint", 0, "int", 0)
		VarSetCapacity(wString, nSize*2)   
		DllCall("MultiByteToWideChar", "uint", 0, "uint", 0, Ptr, &sString, "int", -1, Ptr, &wString, "int", nSize)
	}
	DllCall("gdiplus\GdipMeasureString", Ptr, pGraphics, Ptr, A_IsUnicode ? &sString : &wString, "int", -1, Ptr, hFont, Ptr, &RectF, Ptr, hFormat, Ptr, &RC, "uint*", Chars, "uint*", Lines)
	return &RC ? NumGet(RC, 0, "float") "|" NumGet(RC, 4, "float") "|" NumGet(RC, 8, "float") "|" NumGet(RC, 12, "float") "|" Chars "|" Lines : 0
}
CreateRect(ByRef Rect, x, y, w, h){
	VarSetCapacity(Rect, 16)
	NumPut(x, Rect, 0, "uint"), NumPut(y, Rect, 4, "uint"), NumPut(w, Rect, 8, "uint"), NumPut(h, Rect, 12, "uint")
}
CreateSizeF(ByRef SizeF, w, h){
   VarSetCapacity(SizeF, 8)
   NumPut(w, SizeF, 0, "float"), NumPut(h, SizeF, 4, "float")     
}
CreatePointF(ByRef PointF, x, y){
   VarSetCapacity(PointF, 8)
   NumPut(x, PointF, 0, "float"), NumPut(y, PointF, 4, "float")     
}
Gdip_DrawArc(pGraphics, pPen, x, y, w, h, StartAngle, SweepAngle){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("gdiplus\GdipDrawArc", Ptr, pGraphics, Ptr, pPen, "float", x, "float", y, "float", w, "float", h, "float", StartAngle, "float", SweepAngle)
}
Gdip_DrawPie(pGraphics, pPen, x, y, w, h, StartAngle, SweepAngle){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("gdiplus\GdipDrawPie", Ptr, pGraphics, Ptr, pPen, "float", x, "float", y, "float", w, "float", h, "float", StartAngle, "float", SweepAngle)
}
Gdip_DrawLine(pGraphics, pPen, x1, y1, x2, y2){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("gdiplus\GdipDrawLine", Ptr, pGraphics, Ptr, pPen, "float", x1, "float", y1, "float", x2, "float", y2)
}
Gdip_DrawLines(pGraphics, pPen, Points){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	StringSplit, Points, Points, |
	VarSetCapacity(PointF, 8*Points0)   
	Loop, %Points0%
	{
		StringSplit, Coord, Points%A_Index%, `,
		NumPut(Coord1, PointF, 8*(A_Index-1), "float"), NumPut(Coord2, PointF, (8*(A_Index-1))+4, "float")
	}
	return DllCall("gdiplus\GdipDrawLines", Ptr, pGraphics, Ptr, pPen, Ptr, &PointF, "int", Points0)
}
Gdip_FillRectangle(pGraphics, pBrush, x, y, w, h){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("gdiplus\GdipFillRectangle", Ptr, pGraphics, Ptr, pBrush, "float", x, "float", y, "float", w, "float", h)
}
Gdip_FillRoundedRectangle(pGraphics, pBrush, x, y, w, h, r){
	Region := Gdip_GetClipRegion(pGraphics)
	Gdip_SetClipRect(pGraphics, x-r, y-r, 2*r, 2*r, 4)
	Gdip_SetClipRect(pGraphics, x+w-r, y-r, 2*r, 2*r, 4)
	Gdip_SetClipRect(pGraphics, x-r, y+h-r, 2*r, 2*r, 4)
	Gdip_SetClipRect(pGraphics, x+w-r, y+h-r, 2*r, 2*r, 4)
	E := Gdip_FillRectangle(pGraphics, pBrush, x, y, w, h)
	Gdip_SetClipRegion(pGraphics, Region, 0)
	Gdip_SetClipRect(pGraphics, x-(2*r), y+r, w+(4*r), h-(2*r), 4)
	Gdip_SetClipRect(pGraphics, x+r, y-(2*r), w-(2*r), h+(4*r), 4)
	Gdip_FillEllipse(pGraphics, pBrush, x, y, 2*r, 2*r)
	Gdip_FillEllipse(pGraphics, pBrush, x+w-(2*r), y, 2*r, 2*r)
	Gdip_FillEllipse(pGraphics, pBrush, x, y+h-(2*r), 2*r, 2*r)
	Gdip_FillEllipse(pGraphics, pBrush, x+w-(2*r), y+h-(2*r), 2*r, 2*r)
	Gdip_SetClipRegion(pGraphics, Region, 0)
	Gdip_DeleteRegion(Region)
	return E
}
Gdip_GetClipRegion(pGraphics){
	Region := Gdip_CreateRegion()
	DllCall("gdiplus\GdipGetClip", A_PtrSize ? "UPtr" : "UInt", pGraphics, "UInt*", Region)
	return Region
}
Gdip_SetClipRect(pGraphics, x, y, w, h, CombineMode=0){
   return DllCall("gdiplus\GdipSetClipRect",  A_PtrSize ? "UPtr" : "UInt", pGraphics, "float", x, "float", y, "float", w, "float", h, "int", CombineMode)
}
Gdip_SetClipPath(pGraphics, Path, CombineMode=0){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("gdiplus\GdipSetClipPath", Ptr, pGraphics, Ptr, Path, "int", CombineMode)
}
Gdip_ResetClip(pGraphics){
   return DllCall("gdiplus\GdipResetClip", A_PtrSize ? "UPtr" : "UInt", pGraphics)
}
Gdip_FillEllipse(pGraphics, pBrush, x, y, w, h){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("gdiplus\GdipFillEllipse", Ptr, pGraphics, Ptr, pBrush, "float", x, "float", y, "float", w, "float", h)
}
Gdip_FillRegion(pGraphics, pBrush, Region){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("gdiplus\GdipFillRegion", Ptr, pGraphics, Ptr, pBrush, Ptr, Region)
}
Gdip_FillPath(pGraphics, pBrush, Path){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("gdiplus\GdipFillPath", Ptr, pGraphics, Ptr, pBrush, Ptr, Path)
}
Gdip_CreateRegion(){
	DllCall("gdiplus\GdipCreateRegion", "UInt*", Region)
	return Region
}
Gdip_DeleteRegion(Region){
	return DllCall("gdiplus\GdipDeleteRegion", A_PtrSize ? "UPtr" : "UInt", Region)
}
Gdip_CreateBitmap(Width, Height, Format=0x26200A){
    DllCall("gdiplus\GdipCreateBitmapFromScan0", "int", Width, "int", Height, "int", 0, "int", Format, A_PtrSize ? "UPtr" : "UInt", 0, A_PtrSize ? "UPtr*" : "uint*", pBitmap)
    Return pBitmap
}
Gdip_SetSmoothingMode(pGraphics, SmoothingMode){
   return DllCall("gdiplus\GdipSetSmoothingMode", A_PtrSize ? "UPtr" : "UInt", pGraphics, "int", SmoothingMode)
}
Gdip_DrawRectangle(pGraphics, pPen, x, y, w, h){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("gdiplus\GdipDrawRectangle", Ptr, pGraphics, Ptr, pPen, "float", x, "float", y, "float", w, "float", h)
}
Gdip_DrawRoundedRectangle(pGraphics, pPen, x, y, w, h, r){
	Gdip_SetClipRect(pGraphics, x-r, y-r, 2*r, 2*r, 4)
	Gdip_SetClipRect(pGraphics, x+w-r, y-r, 2*r, 2*r, 4)
	Gdip_SetClipRect(pGraphics, x-r, y+h-r, 2*r, 2*r, 4)
	Gdip_SetClipRect(pGraphics, x+w-r, y+h-r, 2*r, 2*r, 4)
	E := Gdip_DrawRectangle(pGraphics, pPen, x, y, w, h)
	Gdip_ResetClip(pGraphics)
	Gdip_SetClipRect(pGraphics, x-(2*r), y+r, w+(4*r), h-(2*r), 4)
	Gdip_SetClipRect(pGraphics, x+r, y-(2*r), w-(2*r), h+(4*r), 4)
	Gdip_DrawEllipse(pGraphics, pPen, x, y, 2*r, 2*r)
	Gdip_DrawEllipse(pGraphics, pPen, x+w-(2*r), y, 2*r, 2*r)
	Gdip_DrawEllipse(pGraphics, pPen, x, y+h-(2*r), 2*r, 2*r)
	Gdip_DrawEllipse(pGraphics, pPen, x+w-(2*r), y+h-(2*r), 2*r, 2*r)
	Gdip_ResetClip(pGraphics)
	return E
}
Gdip_DrawEllipse(pGraphics, pPen, x, y, w, h){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	return DllCall("gdiplus\GdipDrawEllipse", Ptr, pGraphics, Ptr, pPen, "float", x, "float", y, "float", w, "float", h)
}
Gdip_CreateHBITMAPFromBitmap(pBitmap, Background=0xffffffff){
	DllCall("gdiplus\GdipCreateHBITMAPFromBitmap", A_PtrSize ? "UPtr" : "UInt", pBitmap, A_PtrSize ? "UPtr*" : "uint*", hbm, "int", Background)
	return hbm
}
SetImage(hwnd, hBitmap){
	SendMessage, 0x172, 0x0, hBitmap,, ahk_id %hwnd%
	E := ErrorLevel
	DeleteObject(E)
	return E
}
Gdip_FillPolygon(pGraphics, pBrush, Points, FillMode=0){
	Ptr := A_PtrSize ? "UPtr" : "UInt"
	StringSplit, Points, Points, |
	VarSetCapacity(PointF, 8*Points0)   
	Loop, %Points0%
	{
		StringSplit, Coord, Points%A_Index%, `,
		NumPut(Coord1, PointF, 8*(A_Index-1), "float"), NumPut(Coord2, PointF, (8*(A_Index-1))+4, "float")
	}   
	return DllCall("gdiplus\GdipFillPolygon", Ptr, pGraphics, Ptr, pBrush, Ptr, &PointF, "int", Points0, "int", FillMode)
}

	)
	return Gdip_LITE_Part2
}

Set_Partial_Script_Var(){
	New_Partial_Script=
	(% ` Join`r`n
;#SingleInstance,Force
;#NoEnv
;ListLines,Off
;SetBatchLines,-1
;pToken:=Gdip_Startup()






/*
Gui,1:Add,Text,x6 y3 w190 h24 BackgroundTrans gMove_Window 
Gui,1:Add,Text,x360 y5 w15 h15 BackgroundTrans gMin_Window
Gui,1:Add,Text,x380 y5 w15 h15 BackgroundTrans gGuiClose
Gui,1:Color,222222,222222
Gui,1:Font,cWhite s8 
*/

Move_Window(){
	PostMessage,0xA1,2
}

Min_Window(){
	Gui,1:Minimize
}

















	
	
	)
	return New_Partial_Script
}

Set_Custom_Window_Class_Var(){
	Custom_Window_Class_Var =
	(% ` Join`r`n
Class Custom_Window	{
	__New(x:="",y:="",w:=300,h:=200,Name:=1,Options:="+AlwaysOnTop -Caption -DPIScale",Title:="",Background_Bitmap:=""){
		This.X:=x
		This.Y:=y
		This.W:=w 
		This.H:=h 
		This.Name:=Name
		This.Title:=Title
		This.Options:=Options
		This.Background_Bitmap:=Background_Bitmap
		This.Create_Window()
	}
	Create_Window(){
		Gui,% This.Name ":New",%  This.Options " +LastFound"
		This.Hwnd:=WinExist()
		if(This.Background_Bitmap)
			This.Draw_Background_Bitmap()
	}
	Draw_Background_Bitmap(){
		This.Bitmap:=Gdip_CreateHBITMAPFromBitmap(This.Background_Bitmap)
		Gdip_DisposeImage(This.Background_Bitmap)
		Gui,% This.Name ":Add",Picture,% "x0 y0 w" This.W " h" This.H " 0xE" 
		GuiControlGet,hwnd,% This.Name ":hwnd",Static1
		This.Background_Hwnd:=hwnd
		SetImage(This.Background_Hwnd,This.Bitmap)
	}
	Show_Window(){
		if(This.X&&This.Y)
			Gui,% This.Name ":Show",% "x" This.X " y" This.Y " w" This.W " h" This.H,% This.Title
		else if(This.X&&!This.Y)
			Gui,% This.Name ":Show",% "x" This.X  " w" This.W " h" This.H,% This.Title
		else if(!This.X&&This.Y)
			Gui,% This.Name ":Show",% "y" This.Y  " w" This.W " h" This.H,% This.Title
		else 
			Gui,% This.Name ":Show",% " w" This.W " h" This.H,% This.Title
	}
}	
	)
	return Custom_Window_Class_Var
}

Init()
{
	global Init_func
	res := DllCall(Init_func)
	return res
}

SetParam(str_Name, str_Value)
{
	global SetParam_func
	res := DllCall(SetParam_func, Str, str_Name, Str, str_Value)
	return res
}

TextCreate(Font, fontsize, bold, italic, x, y, color, text, shadow, show)
{
	global TextCreate_func
	res := DllCall(TextCreate_func,Str,Font,Int,fontsize,UChar,bold,UChar,italic,Int,x,Int,y,UInt,color,Str,text,UChar,shadow,UChar,show)
	return res
}

TextDestroy(id)
{
	global TextDestroy_func
	res := DllCall(TextDestroy_func,Int,id)
	return res
}




class overlay {
	createAFK() {
		global
		
		if !showoverlay
			return
		
		SetParam("process", "gta_sa.exe")
		loop {
			overlay.watchProcess()
			
			sleep 2000
			IfWinActive, ahk_exe gta_sa.exe
				break
		}
		
		WinGetPos, , , game_width, game_height, ahk_exe gta_sa.exe
		afk_overlay_id := TextCreate(ovfontname, 9, false, false, 1, game_height/2/1.5, 0xFFFFFFFF, "Загружаем...`n`n`n`n", true, true)
		settimer, refreshAfkOverlay, 1000
		SetTimer, checkrefreshAfkOverlayHour, 1000
		currentHourAfkTime := A_Hour
	}
	
	createSupport() {
		global
		
		if !showoverlay
			return
		
		SetParam("process", "gta_sa.exe")
		loop {
			overlay.watchProcess()
			
			sleep 2000
			IfWinActive, ahk_exe gta_sa.exe
				break
		}
		
		WinGetPos, , , game_width, game_height, ahk_exe gta_sa.exe
		sup_overlay_id1 := TextCreate("Segoe UI", 8, false, false, 1, game_height/2/1.2, 0xFFFFFFFF, "", true, true)
		sup_overlay_id2 := TextCreate("Segoe UI", 8, false, false, 1, game_height/2/1.2+12, 0xFFFFFFFF, "", true, true)
		sup_overlay_id3 := TextCreate("Segoe UI", 8, false, false, 1, game_height/2/1.2+12+12, 0xFFFFFFFF, "", true, true)
		sup_overlay_id4 := TextCreate("Segoe UI", 8, false, false, 1, game_height/2/1.2+12+12+12, 0xFFFFFFFF, "", true, true)
		sup_overlay_id5 := TextCreate("Segoe UI", 8, false, false, 1, game_height/2/1.2+12+12+12+12, 0xFFFFFFFF, "", true, true)
		
		sleep 1000
		
		TextSetString(sup_overlay_id1, "")
		TextSetString(sup_overlay_id2, "")
		TextSetString(sup_overlay_id3, "")
		TextSetString(sup_overlay_id4, "")
		TextSetString(sup_overlay_id5, "")
	}
	
	create() {
		global
		if !showoverlay
			return
		
		SetParam("process", "gta_sa.exe")
		loop {
			overlay.watchProcess()
			
			sleep 2000
			IfWinActive, ahk_exe gta_sa.exe
				break
		}
		
		overlay_id := TextCreate(ovfontname, ovsize, false, false, ovx, ovy, 0xFFFFFFFF, "Загружаем...", true, true)
		settimer, refreshOverlay, 1000
	}
	
	destroy() {
		DestroyAllVisual()
	}
	
	watchProcess() {
		loop {
			IfWinActive, ahk_exe gta_sa.exe
				break
		}
	}
}

TextSetShadow(id, shadow)
{
	global TextSetShadow_func
	res := DllCall(TextSetShadow_func,Int,id,UChar,shadow)
	return res
}

TextSetShown(id, show)
{
	global TextSetShown_func
	res := DllCall(TextSetShown_func,Int,id,UChar,show)
	return res
}

TextSetColor(id,color)
{
	global TextSetColor_func
	res := DllCall(TextSetColor_func,Int,id,UInt,color)
	return res
}

TextSetPos(id,x,y)
{
	global TextSetPos_func
	res := DllCall(TextSetPos_func,Int,id,Int,x,Int,y)
	return res
}

TextSetString(id,Text)
{
	global TextSetString_func
	res := DllCall(TextSetString_func,Int,id,Str,Text)
	return res
}

TextUpdate(id,Font,Fontsize,bold,italic)
{
	global TextUpdate_func
	res := DllCall(TextUpdate_func,Int,id,Str,Font,int,Fontsize,UChar,bold,UChar,italic)
	return res
}

BoxCreate(x,y,width,height,Color,show)
{
	global BoxCreate_func
	res := DllCall(BoxCreate_func,Int,x,Int,y,Int,width,Int,height,UInt,Color,UChar,show)
	return res
}

BoxDestroy(id)
{
	global BoxDestroy_func
	res := DllCall(BoxDestroy_func,Int,id)
	return res
}

BoxSetShown(id,Show)
{
	global BoxSetShown_func 
	res := DllCall(BoxSetShown_func,Int,id,UChar,Show)
	return res
}
	
BoxSetBorder(id,height,Show)
{
	global BoxSetBorder_func
	res := DllCall(BoxSetBorder_func,Int,id,Int,height,Int,Show)
	return res
}


BoxSetBorderColor(id,Color)
{
	global BoxSetBorderColor_func 
	res := DllCall(BoxSetBorderColor_func,Int,id,UInt,Color)
	return res
}

BoxSetColor(id,Color)
{
	global BoxSetColor_func
	res := DllCall(BoxSetColor_func,Int,id,UInt,Color)
	return res
}

BoxSetHeight(id,height)
{
	global BoxSetHeight_func
	res := DllCall(BoxSetHeight_func,Int,id,Int,height)
	return res
}

BoxSetPos(id,x,y)
{
	global BoxSetPos_func	
	res := DllCall(BoxSetPos_func,Int,id,Int,x,Int,y)
	return res
}

BoxSetWidth(id,width)
{
	global BoxSetWidth_func
	res := DllCall(BoxSetWidth_func,Int,id,Int,width)
	return res
}

LineCreate(x1,y1,x2,y2,width,color,show)
{
	global LineCreate_func
	res := DllCall(LineCreate_func,Int,x1,Int,y1,Int,x2,Int,y2,Int,Width,UInt,color,UChar,show)
	return res
}

LineDestroy(id)
{
	global LineDestroy_func
	res := DllCall(LineDestroy_func,Int,id)
	return res
}

LineSetShown(id,show)
{
	global LineSetShown_func
	res := DllCall(LineSetShown_func,Int,id,UChar,show)
	return res
}

LineSetColor(id,color)
{
	global LineSetColor_func
	res := DllCall(LineSetColor_func,Int,id,UInt,color)
	return res
}

LineSetWidth(id, width)
{
	global LineSetWidth_func
	res := DllCall(LineSetWidth_func,Int,id,Int,width)
	return res
}

LineSetPos(id,x1,y1,x2,y2)
{
	global LineSetPos_func
	res := DllCall(LineSetPos_func,Int,id,Int,x1,Int,y1,Int,x2,Int,y2)
	return res
}

ImageCreate(path, x, y, rotation, align, show)
{
	global ImageCreate_func
	res := DllCall(ImageCreate_func, Str, path, Int, x, Int, y, Int, rotation, Int, align, UChar, show)
	return res
}

ImageDestroy(id)
{
	global ImageDestroy_func
	res := DllCall(ImageDestroy_func,Int,id)
	return res
}

ImageSetShown(id,show)
{
	global ImageSetShown_func
	res := DllCall(ImageSetShown_func,Int,id,UChar,show)
	return res
}

ImageSetAlign(id,align)
{
	global ImageSetAlign_func
	res := DllCall(ImageSetAlign_func,Int,id,Int,align)
	return res
}

ImageSetPos(id, x, y)
{
	global ImageSetPos_func
	res := DllCall(ImageSetPos_func,Int,id,Int,x, Int, y)
	return res
}

ImageSetRotation(id, rotation)
{
	global ImageSetRotation_func
	res := DllCall(ImageSetRotation_func,Int,id,Int, rotation)
	return res
}

DestroyAllVisual()
{
	global DestroyAllVisual_func
	res := DllCall(DestroyAllVisual_func)
	return res 
}

ShowAllVisual()
{
	global ShowAllVisual_func
	res := DllCall(ShowAllVisual_func)
	return res
}

HideAllVisual()
{
	global HideAllVisual_func
	res := DllCall(HideAllVisual_func )
	return res
}

GetFrameRate()
{
	global GetFrameRate_func
	res := DllCall(GetFrameRate_func )
	return res
}

GetScreenSpecs(ByRef width, ByRef height)
{
	global GetScreenSpecs_func
	res := DllCall(GetScreenSpecs_func, IntP, width, IntP, height)
	return res
}

SetCalculationRatio(width, height)
{
	global SetCalculationRatio_func
	res := DllCall(SetCalculationRatio_func, Int, width, Int, height)
	return res
}

SetOverlayPriority(id, priority)
{
	global SetOverlayPriority_func
	res := DllCall(SetOverlayPriority_func, Int, id, Int, priority)
	return res
}

ExcError(exc) {
	global
	excMessage := exc.Message, excLine := exc.Line
	loop, parse, excMessage, `n
	{
		excMessage := A_LoopField
		break
	}
	
	excText := excMessage " " excLine,
	excText := StrReplace(StrReplace(excText, ".", ""), " ", "_")
	StringUpper, excText, excText
	Gui, 1:+OwnDialogs
	MsgBox, 16, GOS Helper аварийно завершился, % "Произошла непредвиденная разработчиком ошибка. Пожалуйста, сообщите о ней в техническую поддержку, чтобы она не возникала в следующих версиях. Разработчику понадобится код ошибки, вот он:`n`n" excText "."
	exitapp
}

gtarp_api(method, type := "POST") {
	global
	try whr := ComObjCreate("WinHttp.WinHttpRequest.5.1")
	try whr.Open(type, "http://launcher.gtarp.ru/api.php", true)
	try whr.SetRequestHeader("User-Agent", "GOS Helper")
	try whr.SetRequestHeader("Content-Type","application/x-www-form-urlencoded")
	try whr.Send(method)
	try whr.WaitForResponse()
	try response := whr.ResponseText
	catch e {
		MsgBox, 16, % title, % "Ошибка: " e.Message "."
		return false
	}
		
	if !response
	{
		MsgBox, 16, % title, % "Ошибка: ответ сервера пуст."
		return
	}
	
	try JSON = %response%
	try htmldoc := ComObjCreate("htmlfile")
	try Script := htmldoc.Script
	try Script.execScript(" ", "JScript")
	try gtarp_api := Script.eval("(" . JSON . ")")
	catch e {
		MsgBox, 16, % title, % "Ошибка преобразования JSON ответа в объект: " response "`n`nОшибка: " e.Message "."
		return
	}
	
	return response
}

vk_api(method, token) {
	global
	err_code = 0
	StringReplace, method, method, `n, `%newline`%, All
	StringReplace, method, method, `%newline`%, `%0A, All
	StringReplace, method, method, +, `%2B, All
	StringReplace, method, method, #, `%23, All
	random, rid, 1000, 9999
	StringReplace, method, method, `%random_id`%, % rid, All
	MessagePeerRound := Round(MessagePeer)
	StringReplace, method, method, peer_id=%MessagePeer%, peer_id=%MessagePeerRound%
	MessagePeer = % MessagePeerRound
	api_host := "https://api.vk.com/api.php?oauth=1&"
	
	try whr := ComObjCreate("WinHttp.WinHttpRequest.5.1")
	Loop, parse, method, `&
	{
		RegExMatch(A_LoopField, "v=(.*)", loopfieldout)
		if loopfieldout
			text_api := api_host "&method=" method "&access_token=" token
		else
			text_api := api_host "&method=" method "&access_token=" token "&v=5.95"
	}
	
	try whr.Open("POST", text_api, true)
	try whr.SetRequestHeader("User-Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36")
	try whr.SetRequestHeader("Content-Type","application/x-www-form-urlencoded")
	try whr.Send()
	try whr.WaitForResponse()
	try response := whr.ResponseText
	catch {
		chat.show("{4169E1}[VKMSG] {FFFFFF}Ошибка. Не удалось получить ответ сервера.")
		return
	}
	
	console.writeln("VK API | Post request: " method ". Response: " response ".")
	
	if !response
	{
		chat.show("{4169E1}[VKMSG] {FFFFFF}Ошибка. Ответ сервера пуст.")
		return
	}
	
	try JSON = %response%
	try htmldoc := ComObjCreate("htmlfile")
	try Script := htmldoc.Script
	try Script.execScript(" ", "JScript")
	try api := Script.eval("(" . JSON . ")")
	catch e {
		chat.show("{4169E1}[VKMSG] {FFFFFF}Ошибка преобразования JSON ответа в объект: " response "`n`nОшибка: " e.Message ".")
		return
	}
	
	err_code = 0
	try err_code := api.error.error_code
	if err_code
	{
		if err_code = 1
		{
			MsgBox, 16, %title%, ВКонтакте выдал неизвестную ошибку. Попробуйте повторить запрос позже.
		}
		
		if err_code = 2
		{
			MsgBox, 16, %title%, Приложение было выключено. Пересоздайте токен рабочего приложения.
			IniWrite, % "", config.ini, vkauth, token
			reload
		}
		
		if err_code = 3
		{
			MsgBox, 16, %title%, Передан неизвестный метод. Проверьте`, правильно ли указано название вызываемого метода.
			return
		}
		
		if err_code = 4
		{
			MsgBox, 16, %title%, ВКонтакте сообщает о неверной подписи.
			return
		}
		
		if err_code = 5
		{
			MsgBox, 16, %title%, Сессия недействительна. Необходима авторизация.
			IniWrite, % "", config.ini, vkauth, token
			reload
		}
		
		if err_code = 6
		{
			sleep 333
			vk_api(method, token)
			return
		}
		
		if err_code = 7
		{
			Loop, parse, method, `.
			{
				permission := A_LoopField
				break
			}
			
			Gui, +OwnDialogs
			MsgBox, 16, %title%, Приложение не имеет прав для запроса. Перевойдите в аккаунт с помощью токена`, который с правом %permission%.
			IniWrite, % "", %A_Appdata%\StrelProg\config.ini, auth, token
			reload
			exitapp
		}
		
		if err_code = 8
		{
			MsgBox, 16, %title%, Недопустимый синтаксис запроса.
			return
		}
		
		if err_code = 9
		{
			MsgBox, 16, %title%, Слишком много однотипных действий. Нужно сократить число однотипных обращений.
			return
		}
		
		if err_code = 10
		{
			MsgBox, 16, %title%, Произошла внутренняя ошибка сервера.
			return
		}
		
		if err_code = 14
		{
			try captcha_sid := api.error.captcha_sid
			try captcha_img := api.error.captcha_img
			
			vk_api(method "&captcha_sid=" captcha_sid "&captcha_key=" captcha(captcha_img), token)
			return
		}
		
		if err_code = 17
		{
			redirect_uri := api.error.redirect_uri
			try ie := ComObjCreate("InternetExplorer.Application")
			catch {
				iecrash = 1
			}
			try ie.toolbar := false
			catch {
				iecrash = 1
			}
			try ie.visible := true
			catch {
				iecrash = 1
			}
			try ie.navigate(redirect_uri)
			catch {
				iecrash = 1
			}
			
			if iecrash = 1
			{
				MsgBox, 16, %title%, Произошла ошибка при создании объекта. Убедитесь`, что у Вас установлен и обновлен Internet Explorer`, а также не имеется поврежденных файлов.
				return
			}
			
			loop {
				try ie_readystate := ie.ReadyState
				catch {
					return
				}
				
				if ie_readystate = 4
					break
			}
			
			try ie.visible := true
			WinGet, ieid, ID, ahk_class IEFrame
			log("`n[Вход] Ожидание действий пользователя...")
			loop {
				IfWinNotExist, ahk_id %ieid%
				{
					MsgBox, 16, %title%, Запрос не может быть выполнен.
					break
				}
				
				ControlGetText, ielink, Edit1, ahk_id %ieid%
				if ielink contains success
				{
					vk_api(method, token)
					break
				}
			}
			
			process, close, iexplore.exe
		}
		
		IfWinNotActive, ahk_exe gta_sa.exe
			try MsgBox, 16, %title% API, % "Сервер ВКонтакте выдал ошибку: " api.error.error_msg ".", 10
		else
			chat.show("%t Сервер ВКонтакте выдал ошибку: " api.error.error_msg ".")
	}
	
	return response
}

captcha(urltofile)
{
	global
	URLDownloadToFile, % urltofile, %A_temp%\gh_captcha.png
	WinSet, Disable,, ahk_id %mainwid%
	GuiControl, hide, textpagestatic3
	
	Gui, Captcha:Destroy
	Gui, Captcha:-SysMenu +AlwaysOnTop +hwndcaptchawin
	Gui, Captcha:Color, White
	Gui, Captcha:Font, S9 CDefault, Segoe UI
	Gui, Captcha:Add, Picture, x12 y9 w130 h50 vCaptchaImg, %A_Temp%\gh_captcha.png
	Gui, Captcha:Add, Edit, x12 y69 w130 h20 vCaptchaEnter, 
	Gui, Captcha:Add, Button, x12 y99 w130 h30 gCaptchaOK, OK
	Gui, Captcha:Show, w154 h137, Введите капчу
	captchaenter = 0
	settimer, captchaguiclose, 1
	return
	
	captchaguiclose:
	IfWinActive, ahk_id %mainwid%
		WinActivate, ahk_id %captchawin%
		
	if captchaenter
	{
		settimer, captchaguiclose, off
		return
	}
	
	IfWinNotActive, ahk_id %captchawin%
		return
		
	if GetKeyState("Escape", "P")
		goto captchaok
		
	if GetKeyState("Enter", "P")
		goto captchaok
	
	return
	
	captchaok:
	gui, captcha:submit, nohide
	if !captchaenter
		return
	
	settimer, captchaguiclose, off
	gui, captcha:destroy
	WinSet, Enable,, ahk_id %mainwid%
	return CaptchaEnter
}

updateMe() {
	GuiControl, 1:, StartControlText, Обновление программы...
	RegRead, path, HKEY_LOCAL_MACHINE, SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\GOSHELPER, UninstallString
	Run, %path% /update,, UseErrorLevel
	if errorlevel
	{
		Gui, +OwnDialogs
		MsgBox, 0, GOS Helper, Пожалуйста`, установите программу через установщик.
		exitapp
	}
	exitapp
}

GetAudioDuration( mFile ) { ; SKAN [url] www.autohotkey.com/forum/viewtopic.php?p=361791#361791[url]

 VarSetCapacity( DN,16 ), DLLFunc := "winmm.dll\mciSendString" ( A_IsUnicode ? "W" : "A" )
 DllCall( DLLFunc, Str,"open " """" mFile """" " Alias MP3", UInt,0, UInt,0, UInt,0 )
 DllCall( DLLFunc, Str,"status MP3 length", Str,DN, UInt,16, UInt,0 )
 DllCall( DLLFunc, Str,"close MP3", UInt,0, UInt,0, UInt,0 )
 Return DN
}

FormatSeconds(NumberOfSeconds) {

 time = 20010101 ;1/1/2001
 time += NumberOfSeconds, seconds
 FormatTime, y, %time%, y
 FormatTime, M, %time%, M
 FormatTime, d, %time%, d
 FormatTime, HHmmss, %time%, m:ss
 Return hhmmss
}

CreateFormData(ByRef retData, ByRef retHeader, objParam) {
   new CreateFormData(retData, retHeader, objParam)
}

SuspendProcess(pid) {
    hProcess := DllCall("OpenProcess", "UInt", 0x1F0FFF, "Int", 0, "Int", pid)
    If (hProcess) {
        DllCall("ntdll.dll\NtSuspendProcess", "Int", hProcess)
        DllCall("CloseHandle", "Int", hProcess)
    }
}
ResumeProcess(pid) {
    hProcess := DllCall("OpenProcess", "UInt", 0x1F0FFF, "Int", 0, "Int", pid)
    If (hProcess) {
        DllCall("ntdll.dll\NtResumeProcess", "Int", hProcess)
        DllCall("CloseHandle", "Int", hProcess)
    }
}
IsProcessSuspended(pid) {
    For thread in ComObjGet("winmgmts:").ExecQuery("Select * from Win32_Thread WHERE ProcessHandle = " pid)
        If (thread.ThreadWaitReason != 5)
            Return False
    Return True
}

autoByteFormat(size, decimalPlaces = 2)
{
    static size1 = "KB", size2 = "MB", size3 = "GB", size4 = "TB"

    sizeIndex := 0

    while (size >= 1024)
    {
        sizeIndex++
        size /= 1024.0

        if (sizeIndex = 4)
            break
    }

    return (sizeIndex = 0) ? size " byte" . (size != 1 ? "s" : "")
        : round(size, decimalPlaces) . " " . size%sizeIndex%
}

Percent(int1, int2) {
	return Round(int1 / int2 * 100, 2)
}

isNick(text) {
	loop, parse, text, `_
		index := A_Index
	
	if index <> 2
		return 0
	
	loop, parse, text, `_
	{
		StringLeft, field, A_LoopField, 1
		if (field != str.up(field))
			return 0
		
		loop, parse, A_LoopField, % ""
		{
			if (!str.checkLatin(A_LoopField))
				return 0
		}
	}
	return 1
}

executeFunc(func) {
	StringReplace, func, func, ``n, `n, All
	RegExMatch(func, "i)chat.show, (.*)", ok)
	if ok1
		chat.show(ok1)
	
	RegExMatch(func, "i)dialog.standard, (.*)", ok)
	if ok1
		dialog.standard(ok1)
	
	if (func = "close")
		process, close, gta_sa.exe
	
	return 1
}

findChatLine(text, fLines=10, color=1) { ; fLines - сколько попыток поиска (снизу вверх), по-умолчанию 10.
	line_index = -1
	loop, % fLines
	{
		line_index += 1
		line_text := GetChatLine(line_index)
		if line_text contains %text%
		{
			finded = 1
			break
		}
	}
	
	if finded
	{
		if (color)
			line_text := RegExReplace(line_text, "Ui)\{[a-f0-9]{6}\}")
		
		return line_text
	}
	else
		return 0
}

class CreateFormData
{
   __New(ByRef retData, ByRef retHeader, objParam) {
      CRLF := "`r`n", i, k, v, str, pvData
      ; Create a random Boundary
      Boundary := this.RandomBoundary()
      BoundaryLine := "------------------------------" . Boundary

      this.Len := 0 ; GMEM_ZEROINIT|GMEM_FIXED = 0x40
      this.Ptr := DllCall("GlobalAlloc", UInt, 0x40, UInt, 1, Ptr)

      ; Loop input paramters
      for k, v in objParam
      {
         if IsObject(v) {
            for i, FileName in v
            {
               str := BoundaryLine . CRLF
                    . "Content-Disposition: form-data; name=""" . k . """; filename=""" . FileName . """" . CRLF
                    . "Content-Type: " . this.MimeType(FileName) . CRLF . CRLF
               this.StrPutUTF8( str )
               this.LoadFromFile( Filename )
               this.StrPutUTF8( CRLF )
            }
         }
         else {
            str := BoundaryLine . CRLF
                 . "Content-Disposition: form-data; name=""" . k """" . CRLF . CRLF
                 . v . CRLF
            this.StrPutUTF8( str )
         }
      }
      this.StrPutUTF8( BoundaryLine . "--" . CRLF )

      ; Create a bytearray and copy data in to it.
      retData := ComObjArray(0x11, this.Len)       ; Create SAFEARRAY = VT_ARRAY|VT_UI1
      pvData  := NumGet( ComObjValue( retData ) + 8 + A_PtrSize )
      DllCall("RtlMoveMemory", Ptr, pvData, Ptr, this.Ptr, Ptr, this.Len)

      this.Ptr := DllCall("GlobalFree", Ptr, this.Ptr, Ptr)
      retHeader := "multipart/form-data; boundary=----------------------------" . Boundary
   }

   StrPutUTF8( str ) {
      ReqSz := StrPut( str, "utf-8" ) - 1
      this.Len += ReqSz                                  ; GMEM_ZEROINIT|GMEM_MOVEABLE = 0x42
      this.Ptr := DllCall("GlobalReAlloc", Ptr, this.Ptr, UInt, this.len + 1, UInt, 0x42)   
      StrPut(str, this.Ptr + this.len - ReqSz, ReqSz, "utf-8")
   }
  
   LoadFromFile( Filename ) {
      objFile := FileOpen( FileName, "r" )
      this.Len += objFile.Length                     ; GMEM_ZEROINIT|GMEM_MOVEABLE = 0x42 
      this.Ptr := DllCall("GlobalReAlloc", Ptr, this.Ptr, UInt, this.len, UInt, 0x42)
      objFile.RawRead( this.Ptr + this.Len - objFile.length, objFile.length )
      objFile.Close()
   }

   RandomBoundary() {
      str := "0|1|2|3|4|5|6|7|8|9|a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z"
      Sort, str, D| Random
      str := StrReplace(str, "|")
      Return SubStr(str, 1, 12)
   }

   MimeType(FileName) {
      n := FileOpen(FileName, "r").ReadUInt()
      Return (n        = 0x474E5089) ? "image/png"
           : (n        = 0x38464947) ? "image/gif"
           : (n&0xFFFF = 0x4D42    ) ? "image/bmp"
           : (n&0xFFFF = 0xD8FF    ) ? "image/jpeg"
           : (n&0xFFFF = 0x4949    ) ? "image/tiff"
           : (n&0xFFFF = 0x4D4D    ) ? "image/tiff"
           : "application/octet-stream"
   }
}

SaveScreenshotToFile(x, y, w, h, filePath)  {
   hBitmap := GetHBitmapFromScreen(x, y, w, h)
   gdip := new GDIplus
   pBitmap := gdip.BitmapFromHBitmap(hBitmap)
   DllCall("DeleteObject", Ptr, hBitmap)
   gdip.SaveBitmapToFile(pBitmap, filePath)
   gdip.DisposeImage(pBitmap)
}

GetHBitmapFromScreen(x, y, w, h)  {
   hDC := DllCall("GetDC", Ptr, 0, Ptr)
   hBM := DllCall("CreateCompatibleBitmap", Ptr, hDC, Int, w, Int, h, Ptr)
   pDC := DllCall("CreateCompatibleDC", Ptr, hDC, Ptr)
   oBM := DllCall("SelectObject", Ptr, pDC, Ptr, hBM, Ptr)
   DllCall("BitBlt", Ptr, pDC, Int, 0, Int, 0, Int, w, Int, h, Ptr, hDC, Int, x, Int, y, UInt, 0x00CC0020)
   DllCall("SelectObject", Ptr, pDC, Ptr, oBM)
   DllCall("DeleteDC", Ptr, pDC)
   DllCall("ReleaseDC", Ptr, 0, Ptr, hDC)
   Return hBM  ; should be deleted with DllCall("DeleteObject", Ptr, hBM)
}

class GDIplus   {
   __New()  {
      if !DllCall("GetModuleHandle", Str, "gdiplus", Ptr)
         DllCall("LoadLibrary", Str, "gdiplus")
      VarSetCapacity(si, A_PtrSize = 8 ? 24 : 16, 0), si := Chr(1)
      DllCall("gdiplus\GdiplusStartup", PtrP, pToken, Ptr, &si, Ptr, 0)
      this.token := pToken
   }
   
   __Delete()  {
      DllCall("gdiplus\GdiplusShutdown", Ptr, this.token)
      if hModule := DllCall("GetModuleHandle", Str, "gdiplus", Ptr)
         DllCall("FreeLibrary", Ptr, hModule)
   }
   
   BitmapFromHBitmap(hBitmap, Palette := 0)  {
      DllCall("gdiplus\GdipCreateBitmapFromHBITMAP", Ptr, hBitmap, Ptr, Palette, PtrP, pBitmap)
      return pBitmap  ; should be deleted with this.DisposeImage(pBitmap)
   }
   
   SaveBitmapToFile(pBitmap, sOutput, Quality=75)  {
      SplitPath, sOutput,,, Extension
      if Extension not in BMP,DIB,RLE,JPG,JPEG,JPE,JFIF,GIF,TIF,TIFF,PNG
         return -1

      DllCall("gdiplus\GdipGetImageEncodersSize", UIntP, nCount, UIntP, nSize)
      VarSetCapacity(ci, nSize)
      DllCall("gdiplus\GdipGetImageEncoders", UInt, nCount, UInt, nSize, Ptr, &ci)
      if !(nCount && nSize)
         return -2
      
      Loop, % nCount  {
         sString := StrGet(NumGet(ci, (idx := (48+7*A_PtrSize)*(A_Index-1))+32+3*A_PtrSize), "UTF-16")
         if !InStr(sString, "*." Extension)
            continue
         
         pCodec := &ci+idx
         break
      }
      
      if !pCodec
         return -3

      if RegExMatch(Extension, "i)^J(PG|PEG|PE|FIF)$") && Quality != 75  {
         DllCall("gdiplus\GdipGetEncoderParameterListSize", Ptr, pBitmap, Ptr, pCodec, UintP, nSize)
         VarSetCapacity(EncoderParameters, nSize, 0)
         DllCall("gdiplus\GdipGetEncoderParameterList", Ptr, pBitmap, Ptr, pCodec, UInt, nSize, Ptr, &EncoderParameters)
         Loop, % NumGet(EncoderParameters, "UInt")  {
            elem := (24+A_PtrSize)*(A_Index-1) + 4 + (pad := A_PtrSize = 8 ? 4 : 0)
            if (NumGet(EncoderParameters, elem+16, "UInt") = 1) && (NumGet(EncoderParameters, elem+20, "UInt") = 6)  {
               p := elem+&EncoderParameters-pad-4
               NumPut(Quality, NumGet(NumPut(4, NumPut(1, p+0)+20, "UInt")), "UInt")
               break
            }
         }      
      }
      
      if A_IsUnicode
         pOutput := &sOutput
      else  {
         VarSetCapacity(wOutput, StrPut(sOutput, "UTF-16")*2, 0)
         StrPut(sOutput, &wOutput, "UTF-16")
         pOutput := &wOutput
      }
      E := DllCall("gdiplus\GdipSaveImageToFile", Ptr, pBitmap, Ptr, pOutput, Ptr, pCodec, UInt, p ? p : 0)
      return E ? -5 : 0
   }
   
   DisposeImage(pBitmap)  {
      return DllCall("gdiplus\GdipDisposeImage", Ptr, pBitmap)
   }
}

isFullFraction() {
	RegExMatch(fraction, "(.*) ((.*))", text)
	text := StrReplace(StrReplace(text2, "("), ")")
	ifexist, binders\%text%\удостоверение.ini
		return true
	else
		return false
}

calculateLimit(int) {
	r = 0
	
	if (int < 10) {
		if (str.right(int, 1) != 0)
			r := str.right(int, 1)00
		
		return 3000 - r
	}
	
	if ((int > 9) & (int < 20))  {
		if (str.right(int, 1) != 0)
			r := str.right(int, 1)00
		
		return 2000 - r
	}
	
	if ((int > 19) & (int < 30))  {
		if (str.right(int, 1) != 0)
			r := str.right(int, 1)0
		
		return 1000 - r
	}
	
	if ((int > 29) & (int < 40))  {
		if (str.right(int, 1) != 0)
			r := str.right(int, 1)0
		
		return 900 - r
	}
	
	if ((int > 39) & (int < 50))  {
		if (str.right(int, 1) != 0)
			r := str.right(int, 1)0
		
		return 800 - r
	}
	
	if ((int > 49) & (int < 60))  {
		if (str.right(int, 1) != 0)
			r := str.right(int, 1)0
		
		return 700 - r
	}
	
	if ((int > 59) & (int < 70)) {
		if (str.right(int, 1) != 0)
			r := str.right(int, 1)0
		
		return 600 - r
	}
	
	if ((int > 69) & (int < 80)) {
		if (str.right(int, 1) != 0)
			r := str.right(int, 1)0
		
		return 500 - r
	}
	
	if ((int > 79) & (int < 90)) {
		if (str.right(int, 1) != 0)
			r := str.right(int, 1)0
		
		return 400 - r
	}
	
	if ((int > 89) & (int != 100)) {
		if (str.right(int, 1) != 0)
			r := str.right(int, 1)0
		
		return 300 - r
	}
	else
		return 200
}

checkConfig() {
	global
	
	loop, 2
	{
		dirs = Army_MV,Army_VMF,Police_South,Police_Arzamas,GIBDD,Admin_President,Admin_Batirevo,FBI,SMI,Instructor,CGB_South,CGB_Arzamas
		FileCreateDir, syncwithgame
		FileCreateDir, binders
		FileCreateDir, autoregister
		FileCreateDir, individrp
		
		loop, parse, dirs, `,
		{
			progressText("Создание папки: " A_ProgramFiles "\GOS Helper\autoregister\" A_LoopField "...")
			FileCreateDir, autoregister\%A_LoopField%
		}
		
		loop, parse, dirs, `,
		{
			progressText("Создание папки: " A_ProgramFiles "\GOS Helper\binders\" A_LoopField "...")
			FileCreateDir, binders\%A_LoopField%
		}
		
		progressText("Работаем с реестром...")
		RegWrite, REG_SZ, HKEY_CURRENT_USER, Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers, %gamepath%\gta_sa.exe, WIN7RTM
		
		progressText("Работаем с отыгровками...")
		ifnotexist, binders\ARMY_MV\присяга.ini
		{
			fileappend,
			(
/me встал(а) в стойку смирно
/do Стоит в стойке смирно.
/me открыл(а) книгу
/do Книга открыта.
Я, $myrank $myname $myfamily, торжественно присягаю на верность своей Родине.
Клянусь свято соблюдать Конституцию Российской Федерации.
Клянусь строго выполнять требования воинских уставов.
Клянусь строго выполнять приказы командиров и начальников.
Клянусь достойно исполнять воинский долг.
Клянусь мужественно защищать свободу и независимость.
$myrank $myname $myfamily присягу окончил(а).
/me закрыл(а) книгу
/do Книга закрыта.
			), binders\ARMY_MV\присяга.ini
		}
		
		ifnotexist, binders\ARMY_MV\разборкам4.ini
		{
			fileappend,
			(
/do M4A1 висит на плече.
/me снял(а) M4A1 с плеча
/do M4A1 в руках.
/me положил(а) M4A1 на стол
/do M4A1 на столе.
$myrank $myname $myfamily к разборке M4A1 готов.
/me взял(а) M4A1 в руки
/me отделил(а) магазин и положил на стол
/me вынул(а) пенал с принадлежностями и положил(а) на стол
/me отделил(а) шомпол и положил(а) на стол
/me отделил(а) крышку ствольной коробки и положил(а) на стол
/me отделил(а) возвратный механизм и положил(а) на стол
/me отделил(а) затворную рамку с затвора
/me отделил(а) затвор от затворной рамки и положил(а) на стол
/me отделил(а) газовую трубку со ствольной накладкой и положил(а) на стол
$myrank $myname $myfamily разборку M4A1 закончил.
			), binders\ARMY_MV\разборкам4.ini
	}
	
		ifnotexist, binders\ARMY_MV\сборкам4.ini
		{
			fileappend,
			(
$myrank $myname $myfamily к сборке автомата M4A1 готов.
/me присоединил(а) газовую трубку со ствольной накладкой
/me присоединил(а) затвор к затворной рамке
/me присоединил(а) затворную рамку с затвором к ствольной коробке
/me присоединил(а) возвратный механизм
/me присоединил(а) крышку ствольной коробки
/me спустил(а) курок с боевого взвода и поставил(а) на предохранитель
/me присоединил(а) шомпол
/me вложил(а) пенал в гнездо приклада
/me присоединил(а) магазин к автомату
/me положил(а) M4A1 на стол
$myrank $myname $myfamily сборку M4A1 закончил(а).
			), binders\ARMY_MV\сборкам4.ini
		}
		
		ifnotexist, binders\ARMY_MV\удостоверение.ini
		{
			fileappend,
			(
Здравия желаю, я - $myrank Армии МВ $myname $myfamily.
/me отдал(а) воинское приветствие
/do Значок Армии "Мотострелковые Войск" на плече.
/do Удостоверение в левом кармане.
/me засовывает руку в карман
/me Рука в кармане.
/me достал(а) удостоверение и показал $name $family
/showpass $id
/me закрывает удостоверение
/do Удостоверение закрыто.
/me убирает удостоверение в карман
/do Удостоверение в кармане.
			), binders\ARMY_MV\удостоверение.ini
		}
		
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
		
		ifnotexist, binders\ARMY_VMF\присяга.ini
		{
			fileappend,
			(
/me встал(а) в стойку смирно
/me открыл(а) книгу, лежащую в руках
Я, $myrank $myname, $myfamily, торжественно присягаю на верность своей Родине.
/s Клянусь свято соблюдать Конституцию Российской Федерации.
/s Cтрого выполнять требования воинских уставов, приказы командиров и начальников.
/s Клянусь достойно исполнять воинский долг, мужественно защищать свободу и независимость.
/s Клянусь мужественно защищать конституционный строй России, народ и Отечество.
/s $myramk $myname, $myfamily присягу окончил(а).
/me закрыл(а) книгу с Военной Присягой.
/s Служу Российской Федерации!
			), binders\ARMY_VMF\присяга.ini
		}
		
		ifnotexist, binders\ARMY_VMF\разборкам4.ini
		{
			fileappend,
			(
/do M4A1 висит на плече.
/me снял(а) M4A1 с плеча
/do M4A1 в руках.
/me положил(а) M4A1 на стол
/do M4A1 на столе.
$myrank $myname $myfamily к разборке M4A1 готов.
/me взял(а) M4A1 в руки
/me отделил(а) магазин и положил на стол
/me вынул(а) пенал с принадлежностями и положил(а) на стол
/me отделил(а) шомпол и положил(а) на стол
/me отделил(а) крышку ствольной коробки и положил(а) на стол
/me отделил(а) возвратный механизм и положил(а) на стол
/me отделил(а) затворную рамку с затвора
/me отделил(а) затвор от затворной рамки и положил(а) на стол
/me отделил(а) газовую трубку со ствольной накладкой и положил(а) на стол
$myrank $myname $myfamily разборку M4A1 закончил.
			), binders\ARMY_VMF\разборкам4.ini
	}
	
		ifnotexist, binders\ARMY_VMF\сборкам4.ini
		{
			fileappend,
			(
$myrank $myname $myfamily к сборке автомата M4A1 готов.
/me присоединил(а) газовую трубку со ствольной накладкой
/me присоединил(а) затвор к затворной рамке
/me присоединил(а) затворную рамку с затвором к ствольной коробке
/me присоединил(а) возвратный механизм
/me присоединил(а) крышку ствольной коробки
/me спустил(а) курок с боевого взвода и поставил(а) на предохранитель
/me присоединил(а) шомпол
/me вложил(а) пенал в гнездо приклада
/me присоединил(а) магазин к автомату
/me положил(а) M4A1 на стол
$myrank $myname $myfamily сборку M4A1 закончил(а).
			), binders\ARMY_VMF\сборкам4.ini
		}
		
		ifnotexist, binders\ARMY_VMF\удостоверение.ini
		{
			fileappend,
			(
Здравия желаю, я «$myrank» ВМФ «$myname, $myfamily».
/me движением руки достал(а) удостоверение из правого кармана пиджака
/do Удостоверение в руке.
/me открыл(а) удостоверение и провел им перед глазами человека напротив
/do Удостоверение показано.
/showud $id
/me выждав некоторое время забрал(а) удостоверение и положил в пиджак
/do Удостоверение в пиджаке.
			), binders\ARMY_VMF\удостоверение.ini
		}
		
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
		
		ifnotexist, binders\Admin_Batirevo\удостоверение.ini
		{
			fileappend,
			(
Здравствуйте, я $myrank Администрации Батырево $myname $myfamily
/do Значок Администрации Батырево на груди.
/do Удостоверение в левом кармане.
/me просунул(а) руку в карман, затем достал(а) удостоверение и раскрыл его.
/showpass $id
/me закрыл(а) удостоверение и положил(а) в карман
/do Удостоверение в кармане.
			), binders\Admin_Batirevo\удостоверение.ini
		}
		
		ifnotexist, binders\Admin_Batirevo\адвокат1.ini
		{
			fileappend,
			(
Здравствуйте, я Адвокат. Зовут меня $myname $myfamily.
Кто хочет воспользоваться моими услугами и досрочно выйти из тюрьмы?
Предупреждаю вас, мои услуги стоят 5000-10000 рублей.
Банковские карты не принимаются, иметь с собой эту сумму.
			), binders\Admin_Batirevo\адвокат1.ini
		}
		
		ifnotexist, binders\Admin_Batirevo\адвокат2.ini
		{
			fileappend,
			(
Так... На сколько вас посадили?
/b /jtime
Вы осознаёте за что вас посадили?
Сейчас оформим бланк и освобожу вас.
			), binders\Admin_Batirevo\адвокат2.ini
		}
		
		ifnotexist, binders\Admin_Batirevo\адвокат3.ini
		{
			fileappend,
			(
/me достал(а) бланк и ручку.
/do Бланк с ручкой в руке.
/me начал(а) заполнять бланк.
/do Заполнение... [1/3].
/do Заполнение... [2/3].
/do Заполнение... [3/3].
/me передал(а) бланк и ручку человеку на против.
Распишитесь, пожалуйста.
/b /me расписался
/me забрал(а) бланк и ручку у человека на против
/me закончил(а) заполнение и положил бланк в папку
/me достал(а) дубликат ключей из пиджака
/do Ключи в руке.
/me открыл(а) камеру и выпустил заключённого
/me закрыл(а) камеру заключенных
/me убрал(а) дубликат ключей обратно в пиджак
/unjail $id
			), binders\Admin_Batirevo\адвокат3.ini
		}
		
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

		ifnotexist, binders\Admin_President\удостоверение.ini
		{
			fileappend,
			(
Здравствуйте, я $myrank Администрации Президента $myname $myfamily
/do Значок Администрации Президента на груди.
/do Удостоверение в левом кармане.
/me просунул(а) руку в карман, затем достал(а) удостоверение и раскрыл его.
/showpass $id
/me закрыл(а) удостоверение и положил(а) в карман
/do Удостоверение в кармане.
			), binders\Admin_President\удостоверение.ini
		}
		
		ifnotexist, binders\Admin_President\адвокат1.ini
		{
			fileappend,
			(
Здравствуйте, я Адвокат. Зовут меня $myname $myfamily.
Кто хочет воспользоваться моими услугами и досрочно выйти из тюрьмы?
Предупреждаю вас, мои услуги стоят 5000-10000 рублей.
Банковские карты не принимаются, иметь с собой эту сумму.
			), binders\Admin_President\адвокат1.ini
		}
		
		ifnotexist, binders\Admin_President\адвокат2.ini
		{
			fileappend,
			(
Так... На сколько вас посадили?
/b /jtime
Вы осознаёте за что вас посадили?
Сейчас оформим бланк и освобожу вас.
			), binders\Admin_President\адвокат2.ini
		}
		
		ifnotexist, binders\Admin_President\адвокат3.ini
		{
			fileappend,
			(
/me достал(а) бланк и ручку.
/do Бланк с ручкой в руке.
/me начал(а) заполнять бланк.
/do Заполнение... [1/3].
/do Заполнение... [2/3].
/do Заполнение... [3/3].
/me передал(а) бланк и ручку человеку на против.
Распишитесь, пожалуйста.
/b /me расписался
/me забрал(а) бланк и ручку у человека на против
/me закончил(а) заполнение и положил бланк в папку
/me достал(а) дубликат ключей из пиджака
/do Ключи в руке.
/me открыл(а) камеру и выпустил заключённого
/me закрыл(а) камеру заключенных
/me убрал(а) дубликат ключей обратно в пиджак
/unjail $id
			), binders\Admin_President\адвокат3.ini
		}
		
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
		
		ifnotexist, binders\CGB_Arzamas\клятва.ini
		{
			fileappend,
			(
/me сел(а) на одно колено
/me сидит
/me достал(а) клятву Гиппократа
/do Клятва Гиппократа перед глазами.
/me читает
"Клянусь Аполлоном, врачом Асклепием, Гигеей и Панакеей, всеми богами и богинями, беря их в свидетели..
... посвятить свою жизнь служению человечеству,
/me читает
Здоровье моего пациента будет основной моей заботой, буду уважать доверенные мне тайны,
/me читает
К своим коллегам я буду относиться как к братьям,
/me читает
Даже под угрозой я не буду использовать свои знания против законов человечности.
/me читает
Я обещаю это торжественно, добровольно и чистосердечно.
/do Закончил(а) читать.
/me встал(а)
			), binders\CGB_Arzamas\клятва.ini
		}
		
		ifnotexist, binders\CGB_Arzamas\удостоверение.ini
		{
			fileappend,
			(
Здравствуйте, я $myrank Скорой Помощи г.Арзамаса: $myname $myfamily
/do Бейджик "Должность" на груди.
Чем могу Вам помочь?
			), binders\CGB_Arzamas\удостоверение.ini
		}
		
		ifnotexist, binders\CGB_Arzamas\лечить1.ini
		{
			fileappend,
			(
Предупреждаю, прежде чем я смогу вас вылечить вы должны занять койку
/b Подойдите к свободной койке и нажмите H
			), binders\CGB_Arzamas\лечить1.ini
		}
		
		ifnotexist, binders\CGB_Arzamas\лечить2.ini
		{
			fileappend,
			(
/do Медицинская сумка на плече.
/me снял медицинскую сумку
/me открыв медицинскую сумку, нашел упаковку таблеток
/me открыл упаковку таблеток и выдавил одну таблетку из упаковки
/me передал таблетку человеку напротив
/heal $id
Скоро головная боль утихнет и Вам станет намного лучше.
Всего Вам доброго.
			), binders\CGB_Arzamas\лечить2.ini
		}
		
		ifnotexist, binders\CGB_Arzamas\лечитьхп.ini
		{
			fileappend,
			(
Сейчас я вас выпишу.
/me снял медицинскую сумку затем нашел упаковку таблеток "Пенталгин"
/b Как я закончу пропишите /accheal.
/do Упаковка таблеток "Пенталгин" в руке.
/me открыл упаковку таблеток и выдавил одну таблетку из упаковки
/me передал таблетку человеку напротив
/healhp $id
Скоро головная боль утихнет и Вам станет намного лучше.
			), binders\CGB_Arzamas\лечитьхп.ini
		}
		
		ifnotexist, binders\CGB_Arzamas\лечитьорви.ini
		{
			fileappend,
			(
/do Медицинская сумка на плече.
/me снял медицинскую сумку
/do Медицинская сумка снята.
/me открыв медицинскую сумку, достал чистые перчатки
/me надел чистые перчатки
/do Чистые перчатки одеты.
/me достал одноразовый ватный тампон
/do Ватный тампон пропитанный спиртом в руке.
/me протёр место укола тампоном затем достал шприц с лекарством "Анальгин"
/do Шприц руке.
/me поставил укол человеку напротив
/syringe $id
/me положил шприц на тумбочку затем нашел упаковку таблеток в медицинской сумке
/do Упаковка таблеток "Эргоферон" в руке.
/me открыл упаковку таблеток и выдавил одну таблетку из упаковки
/do Таблетка "Эргоферон" в руке.
/me передал таблетку человеку напротив
/healorvi $id
Скоро температура понизится и Вам станет намного лучше. За следующим сеансом...
... можете подойти через 3 часа. Удачного Вам дня.
			), binders\CGB_Arzamas\лечитьорви.ini
		}
		
		ifnotexist, binders\CGB_Arzamas\лечитьнарко1.ini
		{
			fileappend,
			(
Разрешите Ваш паспорт?
Сейчас я заполню бланк и мы приступим к процедуре.
/me Достал бланк и ручку
/me Вписал ФИО больного
/me Поставил подпись и печать "ЦГБ - А".
Распишитесь на согласие в процедуре.
/b /me Расписался
			), binders\CGB_Arzamas\лечитьнарко1.ini
		}
		
		ifnotexist, binders\CGB_Arzamas\лечитьнарко2.ini
		{
			fileappend,
			(
Хорошо присаживайтесь, затем снимайте всю верхнюю одежду. 
/me помыл руки и одел перчатки
/me достал аптечку и открыл её
/me достал шприц
/me протёр ваткой место укола 
/do Детоксикация...
/me достал аппарат "Налтрексон"
/me поставил капельницу и подключил к ней аппарат
/do Очищение крови...
/me отключил аппарат и убрал капельницу
/seans $id
Cеанс прошел хорошо, приходите через 3 часа. Всего доброго.
			), binders\CGB_Arzamas\лечитьнарко2.ini
		}
		
		ifnotexist, binders\CGB_Arzamas\лечитьхобл.ini
		{
			fileappend,
			(
/do Медицинская сумка на плече.
/me открыв медицинскую сумку, достал чистые перчатки
/me надел чистые перчатки
/me достал одноразовый ватный тампон
/me протёр место укола тампоном
/me затем достал шприц с лекарством "Инсперон"
/syringe $id
/me положил шприц на тумбочку
/me открыл упаковку таблеток и выдавил одну таблетку из упаковки
/me передал таблетку человеку напротив
/healhobl $id
Скоро Вам станет намного лучше.
Не курите так много.
			), binders\CGB_Arzamas\лечитьхобл.ini
		}

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

		ifnotexist, binders\CGB_South\клятва.ini
		{
			fileappend,
			(
/me сел(а) на одно колено
/me сидит
/me достал(а) клятву Гиппократа
/do Клятва Гиппократа перед глазами.
/me читает
"Клянусь Аполлоном, врачом Асклепием, Гигеей и Панакеей, всеми богами и богинями, беря их в свидетели..
... посвятить свою жизнь служению человечеству,
/me читает
Здоровье моего пациента будет основной моей заботой, буду уважать доверенные мне тайны,
/me читает
К своим коллегам я буду относиться как к братьям,
/me читает
Даже под угрозой я не буду использовать свои знания против законов человечности.
/me читает
Я обещаю это торжественно, добровольно и чистосердечно.
/do Закончил(а) читать.
/me встал
			), binders\CGB_South\клятва.ini
		}
		
		ifnotexist, binders\CGB_South\удостоверение.ini
		{
			fileappend,
			(
Здравствуйте, я $myrank Скорой Помощи г.Южного: $myname $myfamily
/do Бейджик "Должность" на груди.
Чем могу Вам помочь?
			), binders\CGB_South\удостоверение.ini
		}
		
		ifnotexist, binders\CGB_South\лечить1.ini
		{
			fileappend,
			(
Предупреждаю, прежде чем я смогу вас вылечить вы должны занять койку
/b Подойдите к свободной койке и нажмите H
			), binders\CGB_South\лечить1.ini
		}
		
		ifnotexist, binders\CGB_South\лечить2.ini
		{
			fileappend,
			(
/do Медицинская сумка на плече.
/me снял медицинскую сумку
/me открыв медицинскую сумку, нашел упаковку таблеток
/me открыл упаковку таблеток и выдавил одну таблетку из упаковки
/me передал таблетку человеку напротив
/heal $id
Скоро головная боль утихнет и Вам станет намного лучше.
Всего Вам доброго.
			), binders\CGB_South\лечить2.ini
		}
		
		ifnotexist, binders\CGB_South\лечитьхп.ini
		{
			fileappend,
			(
Сейчас я вас выпишу.
/me снял медицинскую сумку затем нашел упаковку таблеток "Пенталгин"
/b Как я закончу пропишите /accheal.
/do Упаковка таблеток "Пенталгин" в руке.
/me открыл упаковку таблеток и выдавил одну таблетку из упаковки
/me передал таблетку человеку напротив
/healhp $id
Скоро головная боль утихнет и Вам станет намного лучше.
			), binders\CGB_South\лечитьхп.ini
		}
		
		ifnotexist, binders\CGB_South\лечитьорви.ini
		{
			fileappend,
			(
/do Медицинская сумка на плече.
/me снял медицинскую сумку
/do Медицинская сумка снята.
/me открыв медицинскую сумку, достал чистые перчатки
/me надел чистые перчатки
/do Чистые перчатки одеты.
/me достал одноразовый ватный тампон
/do Ватный тампон пропитанный спиртом в руке.
/me протёр место укола тампоном затем достал шприц с лекарством "Анальгин"
/do Шприц руке.
/me поставил укол человеку напротив
/syringe $id
/me положил шприц на тумбочку затем нашел упаковку таблеток в медицинской сумке
/do Упаковка таблеток "Эргоферон" в руке.
/me открыл упаковку таблеток и выдавил одну таблетку из упаковки
/do Таблетка "Эргоферон" в руке.
/me передал таблетку человеку напротив
/healorvi $id
Скоро температура понизится и Вам станет намного лучше. За следующим сеансом...
... можете подойти через 3 часа. Удачного Вам дня.
			), binders\CGB_South\лечитьорви.ini
		}
		
		ifnotexist, binders\CGB_South\лечитьнарко1.ini
		{
			fileappend,
			(
Разрешите Ваш паспорт?
Сейчас я заполню бланк и мы приступим к процедуре.
/me Достал бланк и ручку
/me Вписал ФИО больного
/me Поставил подпись и печать "ЦГБ - Ю".
Распишитесь на согласие в процедуре.
/b /me Расписался
			), binders\CGB_South\лечитьнарко1.ini
		}
		
		ifnotexist, binders\CGB_South\лечитьнарко2.ini
		{
			fileappend,
			(
Хорошо присаживайтесь, затем снимайте всю верхнюю одежду. 
/me помыл руки и одел перчатки
/me достал аптечку и открыл её
/me достал шприц
/me протёр ваткой место укола 
/do Детоксикация...
/me достал аппарат "Налтрексон"
/me поставил капельницу и подключил к ней аппарат
/do Очищение крови...
/me отключил аппарат и убрал капельницу
/seans $id
Cеанс прошел хорошо, приходите через 3 часа. Всего доброго.
			), binders\CGB_South\лечитьнарко2.ini
		}
		
		ifnotexist, binders\CGB_South\лечитьхобл.ini
		{
			fileappend,
			(
/do Медицинская сумка на плече.
/me открыв медицинскую сумку, достал чистые перчатки
/me надел чистые перчатки
/me достал одноразовый ватный тампон
/me протёр место укола тампоном
/me затем достал шприц с лекарством "Инсперон"
/syringe $id
/me положил шприц на тумбочку
/me открыл упаковку таблеток и выдавил одну таблетку из упаковки
/me передал таблетку человеку напротив
/healhobl $id
Скоро Вам станет намного лучше.
Не курите так много.
			), binders\CGB_South\лечитьхобл.ini
		}

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

		ifnotexist, binders\FBI\удостоверение.ini
		{
			fileappend,
			(
Здравствуйте, я Сотрудник ФСБ $myname $myfamily.
/do Удостоверение и прикреплённый к нему именной жетон лежат в кармане пиджака.
/do На корочке удостоверения надпись золотыми буквами - «Управление Собственной Безопасности»
/me сунул руку в карман, взял удостоверение, раскрыл его на уровне глаз $name $family
/showud $id
/do Выждал пять секунд, тем самым дав человеку напротив прочитать содержимое удостоверения.
/me закрыл удостоверение и убрал его во внутренний карман пиджака
/do Удостоверение в кармане пиджака.
			), binders\FBI\удостоверение.ini
		}
		
		ifnotexist, binders\FBI\обыск.ini
		{
			fileappend,
			(
Сейчас будет произведен досмотр ваших личных вещей на предмет запрещенных объектов,стойте спокойно и не дергайтесь.
/me включил(а) запись на нагрудной камере, достал(а) одноразовые перчатки и надел(а) их на обе руки
/me предъявил(а) проверяемому ордер на обыск с печатью и подписью Ген.Прокурора области
/me приподнял(а) руки проверяемого, провел(а) руками вдоль туловища, ног, залез(а) в карманы проверяемого
/frisk $id
			), binders\FBI\обыск.ini
		}
		
		ifnotexist, binders\FBI\взять.ini
		{
			fileappend,
			(
/me вытащил(а) из кармана человека напротив запрещенные предметы/права
/do Запрещенные предметы/права в руке.
/me убрал(а) предметы во внутренний карман
/take $id
			), binders\FBI\взять.ini
		}
		
		ifnotexist, binders\FBI\розыск.ini
		{
			fileappend,
			(
/me достал(а) из кармана КПК, введя личный пароль авторизовался в базе данных МВД/МО
/me ввел(а) данные о нарушителе, прикрепил(а) ранее сделанные фото нарушителя с места преступления
/do На экран КПК вывелась фотография нарушителя, а также инормация полученная из БД по фото.
/me загрузил(а) данные в список федеральных преступных элементов
/su $id $reason
			), binders\FBI\розыск.ini
		}
		
		ifnotexist, binders\FBI\куфы.ini
		{
			fileappend,
			(
/me взял(а) в руки спец. средства закреплённые на поясе и сразу применил(а) их на нарушителе
/cuff $id
/me проведя болевой приём нарушителю поднял(а) его ноги и повёл за собой 
/drag $id
/pt $id
/do Ведёт за собой задержанного наручниках.
/b Оффнешься - будешь сидеть дополнительные 30 минут!
Вы проходите по ориентировке Федерального Розыска!
			), binders\FBI\куфы.ini
		}
		
		ifnotexist, binders\FBI\штраф.ini
		{
			fileappend,
			(
/me достал(а) из папки необходимые бумаги и начал(а) заполнение протокола
/me записал(а) информацию о нарушителе, данные, причину и дату выписывания протокола
/me заполнил(а) пункт "Ответственность за адм.правонарушение"
/me расписался и передал(а) протокол с копией и ручкой нарушителю для ознакомления
/me забрал(а) подписанный нарушителем оригинал протокола
/do Протокол заполнен, необходимые бумаги убраны в кейс
/ticket $id $sum $reason
В следующий раз не нарушайте.
			), binders\FBI\штраф.ini
		}
		
		ifnotexist, binders\FBI\кпут.ini
		{
			fileappend,
			(
/me согнул(а) преступника
/me посадил(а) его в машину
/cput $id 3
			), binders\FBI\кпут.ini
		}
		
		ifnotexist, binders\FBI\арест.ini
		{
			fileappend,
			(
/me достал(а) ключи от камеры
/me открыл(а) камеру
/me затолкал(а) преступника в камеру
/arrest $id
/me закрыл(а) камеру
/me убрал(а) ключи от камеры в карман
			), binders\FBI\арест.ini
		}

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

		ifnotexist, binders\GIBDD\удостоверение.ini
		{
			fileappend,
			(
Здравия желаю. Вас беспокоит $myrank ГИБДД - $myname $myfamily.
/do Удостоверение сотрудника находится в кармане.
/me достал(а) удостоверение
/do Удостоверение в руках.
/me показал(а) его $name $family
/showud $id
/me подождал(а) некоторое время и положил(а) удостоверение в карман
/do Удостоверение в кармане.
			), binders\GIBDD\удостоверение.ini
		}
		
		ifnotexist, binders\GIBDD\обыск.ini
		{
			fileappend,
			(
Сейчас будет произведен досмотр ваших личных вещей на предмет запрещенных объектов,стойте спокойно и не дергайтесь.
/me включил(а) запись на нагрудной камере, достал(а) одноразовые перчатки и надел(а) их на обе руки
/me предъявил(а) проверяемому ордер на обыск с печатью и подписью Ген.Прокурора области
/me приподнял(а) руки проверяемого, провел(а) руками вдоль туловища, ног, залез(а) в карманы проверяемого
/frisk $id
			), binders\GIBDD\обыск.ini
		}
		
		ifnotexist, binders\GIBDD\взять.ini
		{
			fileappend,
			(
/me вытащил(а) из кармана человека напротив запрещенные предметы/права
/do Запрещенные предметы/права в руке.
/me убрал(а) предметы во внутренний карман
/take $id
			), binders\GIBDD\взять.ini
		}
		
		ifnotexist, binders\GIBDD\розыск.ini
		{
			fileappend,
			(
/me достал(а) из кармана КПК, введя личный пароль авторизовался в базе данных МВД/МО
/me ввел(а) данные о нарушителе, прикрепил(а) ранее сделанные фото нарушителя с места преступления
/do На экран КПК вывелась фотография нарушителя, а также инормация полученная из БД по фото.
/me загрузил(а) данные в список федеральных преступных элементов
/su $id $reason
			), binders\GIBDD\розыск.ini
		}
		
		ifnotexist, binders\GIBDD\куфы.ini
		{
			fileappend,
			(
/me взял(а) в руки спец. средства закреплённые на поясе и сразу применил(а) их на нарушителе
/cuff $id
/me проведя болевой приём нарушителю поднял(а) его ноги и повёл за собой 
/drag $id
/pt $id
/do Ведёт за собой задержанного наручниках.
/b Оффнешься - будешь сидеть дополнительные 30 минут!
Вы проходите по ориентировке Федерального Розыска!
			), binders\GIBDD\куфы.ini
		}
		
		ifnotexist, binders\GIBDD\штраф.ini
		{
			fileappend,
			(
/me достал(а) из папки необходимые бумаги и начал(а) заполнение протокола
/me записал(а) информацию о нарушителе, данные, причину и дату выписывания протокола
/me заполнил(а) пункт "Ответственность за адм.правонарушение"
/me расписался и передал(а) протокол с копией и ручкой нарушителю для ознакомления
/me забрал(а) подписанный нарушителем оригинал протокола
/do Протокол заполнен, необходимые бумаги убраны в кейс
/ticket $id $sum $reason
В следующий раз не нарушайте.
			), binders\GIBDD\штраф.ini
		}
		
		ifnotexist, binders\GIBDD\кпут.ini
		{
			fileappend,
			(
/me согнул(а) преступника
/me посадил(а) его в машину
/cput $id 3
			), binders\GIBDD\кпут.ini
		}
		
		ifnotexist, binders\GIBDD\арест.ini
		{
			fileappend,
			(
/me достал(а) ключи от камеры
/me открыл(а) камеру
/me затолкал(а) преступника в камеру
/arrest $id
/me закрыл(а) камеру
/me убрал(а) ключи от камеры в карман
			), binders\GIBDD\арест.ini
		}

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

		ifnotexist, binders\Instructor\удостоверение.ini
		{
			fileappend,
			(
Здравствуйте, я $myrank Автошколы, зовут меня $myname $myfamily. Чем могу помочь?
			), binders\Instructor\удостоверение.ini
		}
		
		ifnotexist, binders\Instructor\прлиц.ini
		{
			fileappend,
			(
/me взял(а) паспорт у гражданина
/me открыл(а) его на нужной странице
/me достал(а) документы, затем подписал(а) их
/me записал(а) паспортные данные покупателя
/me поставил(а) печать директора автошколы
/me передал(а) лицензию покупателю
Удачного Вам дня
/slic $id
			), binders\Instructor\прлиц.ini
		}

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

		ifnotexist, binders\Police_Arzamas\удостоверение.ini
		{
			fileappend,
			(
Здравия желаю. Вас беспокоит $myrank ОМВД г. Арзамаса - $myname $myfamily.
/do Удостоверение сотрудника находится в кармане.
/me достал(а) удостоверение
/do Удостоверение в руках.
/me показал(а) его $name $family
/showud $id
/me подождал(а) некоторое время и положил(а) удостоверение в карман
/do Удостоверение в кармане.
			), binders\Police_Arzamas\удостоверение.ini
		}
		
		ifnotexist, binders\Police_Arzamas\обыск.ini
		{
			fileappend,
			(
Сейчас будет произведен досмотр ваших личных вещей на предмет запрещенных объектов,стойте спокойно и не дергайтесь.
/me включил(а) запись на нагрудной камере, достал(а) одноразовые перчатки и надел(а) их на обе руки
/me предъявил(а) проверяемому ордер на обыск с печатью и подписью Ген.Прокурора области
/me приподнял(а) руки проверяемого, провел(а) руками вдоль туловища, ног, залез(а) в карманы проверяемого
/frisk $id
			), binders\Police_Arzamas\обыск.ini
		}
		
		ifnotexist, binders\Police_Arzamas\взять.ini
		{
			fileappend,
			(
/me вытащил(а) из кармана человека напротив запрещенные предметы/права
/do Запрещенные предметы/права в руке.
/me убрал(а) предметы во внутренний карман
/take $id
			), binders\Police_Arzamas\взять.ini
		}
		
		ifnotexist, binders\Police_Arzamas\розыск.ini
		{
			fileappend,
			(
/me достал(а) из кармана КПК, введя личный пароль авторизовался в базе данных МВД/МО
/me ввел(а) данные о нарушителе, прикрепил(а) ранее сделанные фото нарушителя с места преступления
/do На экран КПК вывелась фотография нарушителя, а также инормация полученная из БД по фото.
/me загрузил(а) данные в список федеральных преступных элементов
/su $id $reason
			), binders\Police_Arzamas\розыск.ini
		}
		
		ifnotexist, binders\Police_Arzamas\куфы.ini
		{
			fileappend,
			(
/me взял(а) в руки спец. средства закреплённые на поясе и сразу применил(а) их на нарушителе
/cuff $id
/me проведя болевой приём нарушителю поднял(а) его ноги и повёл за собой 
/drag $id
/pt $id
/do Ведёт за собой задержанного наручниках.
/b Оффнешься - будешь сидеть дополнительные 30 минут!
Вы проходите по ориентировке Федерального Розыска!
			), binders\Police_Arzamas\куфы.ini
		}
		
		ifnotexist, binders\Police_Arzamas\штраф.ini
		{
			fileappend,
			(
/me достал(а) из папки необходимые бумаги и начал(а) заполнение протокола
/me записал(а) информацию о нарушителе, данные, причину и дату выписывания протокола
/me заполнил(а) пункт "Ответственность за адм.правонарушение"
/me расписался и передал(а) протокол с копией и ручкой нарушителю для ознакомления
/me забрал(а) подписанный нарушителем оригинал протокола
/do Протокол заполнен, необходимые бумаги убраны в кейс
/ticket $id $sum $reason
В следующий раз не нарушайте.
			), binders\Police_Arzamas\штраф.ini
		}
		
		ifnotexist, binders\Police_Arzamas\кпут.ini
		{
			fileappend,
			(
/me согнул(а) преступника
/me посадил(а) его в машину
/cput $id 3
			), binders\Police_Arzamas\кпут.ini
		}
		
		ifnotexist, binders\Police_Arzamas\арест.ini
		{
			fileappend,
			(
/me достал(а) ключи от камеры
/me открыл(а) камеру
/me затолкал(а) преступника в камеру
/arrest $id
/me закрыл(а) камеру
/me убрал(а) ключи от камеры в карман
			), binders\Police_Arzamas\арест.ini
		}

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

		ifnotexist, binders\Police_South\удостоверение.ini
		{
			fileappend,
			(
Здравия желаю. Вас беспокоит $myrank ОМВД г. Южный - $myname $myfamily.
/do Удостоверение сотрудника находится в кармане.
/me достал(а) удостоверение
/do Удостоверение в руках.
/me показал(а) его $name $family
/showud $id
/me подождал(а) некоторое время и положил(а) удостоверение в карман
/do Удостоверение в кармане.
			), binders\Police_South\удостоверение.ini
		}
		
		ifnotexist, binders\Police_South\обыск.ini
		{
			fileappend,
			(
Сейчас будет произведен досмотр ваших личных вещей на предмет запрещенных объектов,стойте спокойно и не дергайтесь.
/me включил(а) запись на нагрудной камере, достал(а) одноразовые перчатки и надел(а) их на обе руки
/me предъявил(а) проверяемому ордер на обыск с печатью и подписью Ген.Прокурора области
/me приподнял(а) руки проверяемого, провел(а) руками вдоль туловища, ног, залез(а) в карманы проверяемого
/frisk $id
			), binders\Police_South\обыск.ini
		}
		
		ifnotexist, binders\Police_South\взять.ini
		{
			fileappend,
			(
/me вытащил(а) из кармана человека напротив запрещенные предметы/права
/do Запрещенные предметы/права в руке.
/me убрал(а) предметы во внутренний карман
/take $id
			), binders\Police_South\взять.ini
		}
		
		ifnotexist, binders\Police_South\розыск.ini
		{
			fileappend,
			(
/me достал(а) из кармана КПК, введя личный пароль авторизовался в базе данных МВД/МО
/me ввел(а) данные о нарушителе, прикрепил(а) ранее сделанные фото нарушителя с места преступления
/do На экран КПК вывелась фотография нарушителя, а также инормация полученная из БД по фото.
/me загрузил(а) данные в список федеральных преступных элементов
/su $id $reason
			), binders\Police_South\розыск.ini
		}
		
		ifnotexist, binders\Police_South\куфы.ini
		{
			fileappend,
			(
/me взял(а) в руки спец. средства закреплённые на поясе и сразу применил(а) их на нарушителе
/cuff $id
/me проведя болевой приём нарушителю поднял(а) его ноги и повёл за собой 
/drag $id
/pt $id
/do Ведёт за собой задержанного наручниках.
/b Оффнешься - будешь сидеть дополнительные 30 минут!
Вы проходите по ориентировке Федерального Розыска!
			), binders\Police_South\куфы.ini
		}
		
		ifnotexist, binders\Police_South\штраф.ini
		{
			fileappend,
			(
/me достал(а) из папки необходимые бумаги и начал(а) заполнение протокола
/me записал(а) информацию о нарушителе, данные, причину и дату выписывания протокола
/me заполнил(а) пункт "Ответственность за адм.правонарушение"
/me расписался и передал(а) протокол с копией и ручкой нарушителю для ознакомления
/me забрал(а) подписанный нарушителем оригинал протокола
/do Протокол заполнен, необходимые бумаги убраны в кейс
/ticket $id $sum $reason
В следующий раз не нарушайте.
			), binders\Police_South\штраф.ini
		}
		
		ifnotexist, binders\Police_South\кпут.ini
		{
			fileappend,
			(
/me согнул(а) преступника
/me посадил(а) его в машину
/cput $id 3
			), binders\Police_South\кпут.ini
		}
		
		ifnotexist, binders\Police_South\арест.ini
		{
			fileappend,
			(
/me достал(а) ключи от камеры
/me открыл(а) камеру
/me затолкал(а) преступника в камеру
/arrest $id
/me закрыл(а) камеру
/me убрал(а) ключи от камеры в карман
			), binders\Police_South\арест.ini
		}

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

		ifnotexist, binders\SMI\удостоверение.ini
		{
			fileappend, Не нуждается., binders\SMI\удостоверение.ini
		}

		ifnotexist, binders\SMI\эфир1.ini
		{
			fileappend,
			(
…:::Музыкальная заставка Средств Массовой Информации:::…
Доброго времени суток Нижегородская область.
С вами я, $myrank - $myname $myfamily
Мне бы хотелось провести эфир на тему - $theme.
Спонсоров ждем возле $place.
			), binders\SMI\эфир1.ini
		}
		
		ifnotexist, binders\SMI\эфир2.ini
		{
			fileappend,
			(
Поскольку фонд уже набран, то я объясняю правила, и мы - начинаем.
Я буду говорить в микрофон какие-либо вопросы...
...А вы должны быстрее и правильнее всех написать правильный ответ.
Ответы присылаем на номер: $mynumber. Игра будет длиться до четырёх баллов.
Итак. Приготовьтесь.
			), binders\SMI\эфир2.ini
		}
		
		ifnotexist, binders\SMI\эфир3.ini
		{
			fileappend,
			(
На этом мы заканчиваем наш эфир.
Победителя буду ждать возле Казино г."Арзамас"
С вами был я, $myrank - $myname $myfamily.
…:::Музыкальная заставка Средств Массовой Информации:::…
			), binders\SMI\эфир3.ini
		}
		
		ifnotexist, binders\SMI\интервью1.ini
		{
			fileappend,
			(
..::Музыкальная заставка Средств Массовой Информации::..
Доброго времени суток Нижегородская область.
С вами я , $myrank и $myname.
Сегодня я хотел бы провести эфир на тему - "Интервью".
			), binders\SMI\интервью1.ini
		}
		
		ifnotexist, binders\SMI\интервью2.ini
		{
			fileappend,
			(
У нас в гостях - $rank - $name.
Сегодня мы узнаем о нём немного побольше.
Задавайте вопросы на номер - $mynumber
			), binders\SMI\интервью2.ini
		}
		
		ifnotexist, binders\SMI\интервью3.ini
		{
			fileappend,
			(
На этом наш эфир заканчивается.
С вами был $myrank - $myname.
А я напомню, у нас был в гостях $rank - $name.
Всем спасибо.
До скорых встреч!
..::Музыкальная заставка Средств Массовой Информации::..
			), binders\SMI\интервью3.ini
		}
		
		ifnotexist, binders\SMI\погода.ini
		{
			fileappend,
			(
…:::Музыкальная заставка Средств Массовой Информации:::…
Доброго времени суток Нижегородская область.
С вами я, $myrank - $myname $myfamily
И сейчас я расскажу прогноз погоды на сегодня.
В Городке "Южном" сегодня прохладно. Около (15°).
Синоптики рекомендуют в данной области пить больше чая.
В посёлке "Батырево" уж не сильно жарко. (20°)...
... но пасмурно и идёт град.
Синоптики рекомендуют быть дома и закрыть все окна.
В Городке "Арзамас" уже лучше . Около (25°)
А о погоде все . Приятного дня.
…:::Музыкальная заставка Средств Массовой Информации:::…
			), binders\SMI\погода.ini
		}

		progressText("Работаем с автореестром...")
		IfNotExist, autoregister\ARMY_MV\giverank.ini								; АРМИЯ МВ
		{
			FileAppend,
			(
/do Телефон в руках.
/me открыл базу данных "Армия "МВ"
/do База открыта.
/me нашел личное $name $family и открыл
/do Личное дело сотрудника открыто.
/me подписал рапорт, о повышении/понижении сотрудника
/me сорвал погоны с $name $family и передал ему новые
/giverank $id $action
			), autoregister\ARMY_MV\giverank.ini
		}
		
		IfNotExist, autoregister\ARMY_MV\invite.ini
		{
			FileAppend,
			(
/do Телефон в руках.
/me нашел личное дело $name $family
/do Личное дело найдено.
/me внёс личное дело в базу "Армия "МВ"
/me убрал телефон в карман
/me передал форму и погоны $name $family
/invite $id
			), autoregister\ARMY_MV\invite.ini
		}
		
		IfNotExist, autoregister\ARMY_MV\uninvite.ini
		{
			fileappend,
			(
/me достал телефон
/do Телефон в руках
/me зашел в базу "Армия "МВ".
/do Нашёл личное дело $name $family
/me записал данные о сотруднике
/do Данные записаны
/me убрал телефон в карман
/uninvite $id $action
			), autoregister\ARMY_MV\uninvite.ini
		}
		
		IfNotExist, autoregister\Army_VMF\giverank.ini							; АРМИЯ ВМФ
		{
			FileAppend,
			(
/do Телефон в руках.
/me открыл базу данных "Армия "ВМФ"
/do База открыта.
/me нашел личное дело $name $family и открыл
/do Личное дело сотрудника открыто.
/me подписал рапорт, о повышении/понижении сотрудника
/me сорвал погоны с $name $family и передал ему новые
/giverank $id $action
			), autoregister\Army_VMF\giverank.ini
		}
		
		IfNotExist, autoregister\Army_VMF\invite.ini
		{
			FileAppend,
			(
/do Телефон в руках.
/me нашел личное дело $name $family
/do Личное дело найдено.
/me внёс личное дело в базу "Армия "ВМФ"
/me убрал телефон в карман
/me передал форму и погоны $name $family
/invite $id
			), autoregister\Army_VMF\invite.ini
		}
		
		IfNotExist, autoregister\Army_VMF\uninvite.ini
		{
			fileappend,
			(
/me достал телефон
/do Телефон в руках
/me зашел в базу "Армия "ВМФ".
/do Нашёл личное дело $name $family
/me записал данные о $name $family
/do Данные записаны
/me убрал телефон в карман
/uninvite $id $action
			), autoregister\Army_VMF\uninvite.ini
		}
		
		IfNotExist, autoregister\Police_South\giverank.ini							; ПОЛИЦИЯ ЮЖНОГО
		{
			fileappend,
			(
/me сорвал погоны с $name $family
/do Погоны сорваны.
/me достал новые погоны, затем передал сотруднику
/do Погоны у $name $family.
/giverank $id $action
			), autoregister\Police_South\giverank.ini
		}
		
		IfNotExist, autoregister\Police_South\invite.ini
		{
			fileappend,
			(
/me достал пакет с формой для $name $family
/do Пакет с формой в руках.
/me передал форму $name $family
/do Форма у $name $family.
/invite $id
			), autoregister\Police_South\invite.ini
		}
		
		IfNotExist, autoregister\Police_South\uninvite.ini
		{
			fileappend,
			(
/do КПК в руке.
/me зашел в базу 'Полиции'.
/do Поиск сотрудника: $name $family...
/me записал данные о нарушении
/do Данные записаны.
/me спрятал КПК
/uninvite $id $action
			), autoregister\Police_South\uninvite.ini
		}
		
		IfNotExist, autoregister\Police_Arzamas\giverank.ini							; ПОЛИЦИЯ АРЗАМАСА
		{
			fileappend,
			(
/me сорвал погоны с $name $family
/do Погоны сорваны.
/me достал новые погоны, затем передал сотруднику
/do Погоны у $name $family.
/giverank $id $action
			), autoregister\Police_Arzamas\giverank.ini
		}
		
		IfNotExist, autoregister\Police_Arzamas\invite.ini
		{
			fileappend,
			(
/me достал пакет с формой для $name $family
/do Пакет с формой в руках.
/me передал форму $name $family
/do Форма у $name $family.
/invite $id
			), autoregister\Police_Arzamas\invite.ini
		}
		
		IfNotExist, autoregister\Police_Arzamas\uninvite.ini
		{
			fileappend,
			(
/do КПК в руке.
/me зашел в базу 'Полиции'.
/do Поиск сотрудника: $name $family...
/me записал данные о нарушении
/do Данные записаны.
/me спрятал КПК
/uninvite $id $action
			), autoregister\Police_Arzamas\uninvite.ini
		}
		
		IfNotExist, autoregister\GIBDD\giverank.ini							; ГИБДД
		{
			fileappend,
			(
/me сорвал погоны с $name $family
/do Погоны сорваны.
/me достал новые погоны, затем передал сотруднику
/do Погоны у $name $family.
/giverank $id $action
			), autoregister\GIBDD\giverank.ini
		}
		
		IfNotExist, autoregister\GIBDD\invite.ini
		{
			fileappend,
			(
/me достал пакет с формой для $name $family
/do Пакет с формой в руках.
/me передал форму $name $family
/do Форма у $name $family.
/invite $id
			), autoregister\GIBDD\invite.ini
		}
		
		IfNotExist, autoregister\GIBDD\uninvite.ini
		{
			fileappend,
			(
/do КПК в руке.
/me зашел в базу 'Полиции'.
/do Поиск сотрудника: $name $family...
/me записал данные о нарушении
/do Данные записаны.
/me спрятал КПК
/uninvite $id $action
			), autoregister\GIBDD\uninvite.ini
		}
		
		IfNotExist, autoregister\Admin_President\giverank.ini							; Администрация Президента
		{
			fileappend,
			(
/me достал планшет
/me зашел в базу данных
/me выбрал пункт 'Понизить/Повысить' и указал $name $family
/do На экране: сохранение данных...
/giverank $id $action
/me дождался надписи 'Сохранено' и закрыл базу данных
/me убрал планшет
			), autoregister\Admin_President\giverank.ini
		}
		
		IfNotExist, autoregister\Admin_President\invite.ini
		{
			fileappend,
			(
/me достал пакет с формой для $name $family
/do Пакет с формой в руках.
/me передал форму $name $family
/do Форма у $name $family
/invite $id
			), autoregister\Admin_President\invite.ini
		}
		
		IfNotExist, autoregister\Admin_President\uninvite.ini
		{
			FileAppend,
			(
/me открыл КПК
/do КПК в руке.
/me зашел в базу данных.
/do Поиск сотрудника: $name $family...
/me записал данные о нарушении
/do Данные записаны.
/uninvite $id $action
/me спрятал КПК
			), autoregister\Admin_President\uninvite.ini
		}
		
		IfNotExist, autoregister\Admin_Batirevo\giverank.ini							; Администрация Батырево
		{
			fileappend,
			(
/me достал планшет
/me зашел в базу данных
/me выбрал пункт 'Понизить/Повысить' и указал $name $family
/do На экране: сохранение данных...
/giverank $id $action
/me дождался надписи 'Сохранено' и закрыл базу данных
/me убрал планшет
			), autoregister\Admin_Batirevo\giverank.ini
		}
		
		IfNotExist, autoregister\Admin_Batirevo\invite.ini
		{
			fileappend,
			(
/me достал пакет с формой для $name $family
/do Пакет с формой в руках.
/me передал форму $name $family
/do Форма у $name $family
/invite $id
			), autoregister\Admin_Batirevo\invite.ini
		}
		
		IfNotExist, autoregister\Admin_Batirevo\uninvite.ini
		{
			FileAppend,
			(
/me открыл КПК
/do КПК в руке.
/me зашел в базу данных.
/do Поиск сотрудника: $name $family...
/me записал данные о нарушении
/do Данные записаны.
/uninvite $id $action
/me спрятал КПК
			), autoregister\Admin_Batirevo\uninvite.ini
		}
		
		IfNotExist, autoregister\FBI\giverank.ini							; ФСБ
		{
			fileappend,
			(
/me достал планшет
/me зашел в базу данных
/me выбрал пункт 'Понизить/Повысить' и указал $name $family
/do На экране: сохранение данных...
/giverank $id $action
/me дождался надписи 'Сохранено' и закрыл базу данных
/me убрал планшет
			), autoregister\FBI\giverank.ini
		}
		
		IfNotExist, autoregister\FBI\invite.ini
		{
			fileappend,
			(
/me достал пакет с формой для $name $family
/do Пакет с формой в руках.
/me передал форму $name $family
/do Форма у $name $family
/invite $id
			), autoregister\FBI\invite.ini
		}
		
		IfNotExist, autoregister\FBI\uninvite.ini
		{
			FileAppend,
			(
/me открыл КПК
/do КПК в руке.
/me зашел в базу данных.
/do Поиск сотрудника: $name $family...
/me записал данные о нарушении
/do Данные записаны.
/uninvite $id $action
/me спрятал КПК
			), autoregister\FBI\uninvite.ini
		}
		
		IfNotExist, autoregister\FBI\fgiverank.ini
		{
			FileAppend,
			(
/do КПК в кармане.
/me достал КПК из кармана
/me введя личный пароль, авторизовался в «Федеральной Службе Безопасности»
/do На экране КПК: «Учетная запись принадлежит - $myname $myfamily».
/me ввел имя нарушителя - $name $family и открыл его личное дело
/me составляет рапорт о происшествии, прикрепяет доказательства
/me В графе: «Причина понижения» написал - «Нарушение статьи Федерального Постановления»
/me Заполняет графу: «Cчитаю целесообразным нарушителя наказать»
/do В графе написано «Понижение в звании за нарушение Федерального Постановления».
/me Вписал дату нарушения, поставил свою цифровую подпись «$myfamily»
/do Дата нарушения указана, рапорт подписан.
/me зарегистрировал документ в базе данных «ФСБ»
/fgiverank $id $action
/do На экране КПК: «Рапорт составлен. $name $family понижен[Успешно]»
/me резким движением выключил КПК и убрал его в карман
			), autoregister\FBI\fgiverank.ini
		}
		
		IfNotExist, autoregister\FBI\funinvite.ini
		{
			FileAppend,
			(
/do КПК в кармане.
/me достал КПК из кармана
/me введя личный пароль, авторизовался в «Федеральной Службе Безопасности»
/do На экране КПК: «Учетная запись принадлежит - $myname $myfamily».
/me ввел имя нарушителя - $name $family и открыл его личное дело
/me составляет рапорт о происшествии, прикрепяет доказательства
/me В графе: «Причина увольнения» написал - «Нарушение статьи Федерального Постановления»
/me Заполняет графу: «Cчитаю целесообразным нарушителя наказать»
/do В графе написано «Увольнение в звании за нарушение Федерального Постановления».
/me Вписал дату нарушения, поставил свою цифровую подпись - «$myfamily»
/do Дата нарушения указана, рапорт подписан.
/me зарегистрировал документ в базе данных «Федеральной Службе Безопасности»
/funinvite $id
/do На экране КПК: «Рапорт составлен. $name $family понижен[Успешно]».
/me резким движением выключил КПК и убрал его в карман
			), autoregister\FBI\funinvite.ini
		}
		
		IfNotExist, autoregister\SMI\giverank.ini							; СМИ
		{
			fileappend,
			(
/me достал планшет
/me зашел в базу данных
/me выбрал пункт 'Понизить/Повысить' и указал $name $family
/do На экране: сохранение данных...
/giverank $id $action
/me дождался надписи 'Сохранено' и закрыл базу данных
/me убрал планшет
			), autoregister\SMI\giverank.ini
		}
		
		IfNotExist, autoregister\SMI\invite.ini
		{
			fileappend,
			(
/me достал пакет с формой для $name $family
/do Пакет с формой в руках.
/me передал форму $name $family
/do Форма у $name $family
/invite $id
			), autoregister\SMI\invite.ini
		}
		
		IfNotExist, autoregister\SMI\uninvite.ini
		{
			FileAppend,
			(
/me открыл КПК
/do КПК в руке.
/me зашел в базу данных.
/do Поиск сотрудника: $name $family...
/me записал данные о нарушении
/do Данные записаны.
/uninvite $id $action
/me спрятал КПК
			), autoregister\SMI\uninvite.ini
		}
		
		IfNotExist, autoregister\Instructor\giverank.ini							; Инструкторы
		{
			fileappend,
			(
/me достал планшет
/me зашел в базу данных
/me выбрал пункт 'Понизить/Повысить' и указал $name $family
/do На экране: сохранение данных...
/giverank $id $action
/me дождался надписи 'Сохранено' и закрыл базу данных
/me убрал планшет
			), autoregister\Instructor\giverank.ini
		}
		
		IfNotExist, autoregister\Instructor\invite.ini
		{
			fileappend,
			(
/me достал пакет с формой для $name $family
/do Пакет с формой в руках.
/me передал форму $name $family
/do Форма у $name $family
/invite $id
			), autoregister\Instructor\invite.ini
		}
		
		IfNotExist, autoregister\Instructor\uninvite.ini
		{
			FileAppend,
			(
/me открыл КПК
/do КПК в руке.
/me зашел в базу данных.
/do Поиск сотрудника: $name $family...
/me записал данные о нарушении
/do Данные записаны.
/uninvite $id $action
/me спрятал КПК
			), autoregister\Instructor\uninvite.ini
		}
		
		IfNotExist, autoregister\CGB_South\giverank.ini							; ЦГБ Южного
		{
			fileappend,
			(
/me достал планшет
/me зашел в базу данных
/me выбрал пункт 'Понизить/Повысить' и указал $name $family
/do На экране: сохранение данных...
/giverank $id $action
/me дождался надписи 'Сохранено' и закрыл базу данных
/me убрал планшет
			), autoregister\CGB_South\giverank.ini
		}
		
		IfNotExist, autoregister\CGB_South\invite.ini
		{
			fileappend,
			(
/me достал пакет с формой для $name $family
/do Пакет с формой в руках.
/me передал форму $name $family
/do Форма у $name $family
/invite $id
			), autoregister\CGB_South\invite.ini
		}
		
		IfNotExist, autoregister\CGB_South\uninvite.ini
		{
			FileAppend,
			(
/me открыл КПК
/do КПК в руке.
/me зашел в базу данных.
/do Поиск сотрудника: $name $family...
/me записал данные о нарушении
/do Данные записаны.
/uninvite $id $action
/me спрятал КПК
			), autoregister\CGB_South\uninvite.ini
		}
		
		IfNotExist, autoregister\CGB_Arzamas\giverank.ini							; ЦГБ Арзамаса
		{
			fileappend,
			(
/me достал планшет
/me зашел в базу данных
/me выбрал пункт 'Понизить/Повысить' и указал $name $family
/do На экране: сохранение данных...
/giverank $id $action
/me дождался надписи 'Сохранено' и закрыл базу данных
/me убрал планшет
			), autoregister\CGB_Arzamas\giverank.ini
		}
		
		IfNotExist, autoregister\CGB_Arzamas\invite.ini
		{
			fileappend,
			(
/me достал пакет с формой для $name $family
/do Пакет с формой в руках.
/me передал форму $name $family
/do Форма у $name $family
/invite $id
			), autoregister\CGB_Arzamas\invite.ini
		}
		
		IfNotExist, autoregister\CGB_Arzamas\uninvite.ini
		{
			FileAppend,
			(
/me открыл КПК
/do КПК в руке.
/me зашел в базу данных.
/do Поиск сотрудника: $name $family...
/me записал данные о нарушении
/do Данные записаны.
/uninvite $id $action
/me спрятал КПК
			), autoregister\CGB_Arzamas\uninvite.ini
		}
		
		progressText("Чтение конфига: секция roleplay, пункт autorem")
		IniRead, autorem, config.ini, Roleplay, autorem
		if autorem = Error
			IniWrite, 1, config.ini, Roleplay, autorem

		progressText("Чтение конфига: секция roleplay, пункт autogunrp")
		IniRead, autogunrp, config.ini, Roleplay, autogunrp
		if autogunrp = Error
			IniWrite, 1, config.ini, Roleplay, autogunrp
		
		progressText("Чтение конфига: секция game, пункт afktime")
		IniRead, afktime, config.ini, game, afktime
		if afktime = Error
			IniWrite, 1, config.ini, game, afktime
		
		progressText("Чтение конфига: секция roleplay, пункт autotazer")
		IniRead, autotazer, config.ini, Roleplay, autotazer
		if autotazer = Error
			IniWrite, 1, config.ini, Roleplay, autotazer
		
		progressText("Чтение конфига: секция sortscreen, пункт state")
		IniRead, sortscreenstate, config.ini, sortscreen, state
		if sortscreenstate = Error
			IniWrite, 0, config.ini, sortscreen, state
		
		progressText("Чтение конфига: секция vkfuncs, пункт rememberVirtIds")
		IniRead, vkmsg_rememberVirtIds, config.ini, vkfuncs, rememberVirtIds
		if vkmsg_rememberVirtIds = Error
			IniWrite, 1, config.ini, vkfuncs, rememberVirtIds
		
		
		progressText("Чтение конфига: секция vkfuncs, пункт autoread")
		IniRead, vkmsg_autoread, config.ini, vkfuncs, autoread
		if vkmsg_autoread = Error
			IniWrite, 1, config.ini, vkfuncs, autoread
		
		progressText("Чтение конфига: секция vkfuncs, пункт autoplayVoice")
		IniRead, vkmsg_autoplayVoice, config.ini, vkfuncs, autoplayVoice
		if vkmsg_autoplayVoice = Error
			IniWrite, 1, config.ini, vkfuncs, autoplayVoice
		
		progressText("Чтение конфига: секция game, пункт mode_f8time")
		IniRead, mode_f8time, config.ini, game, mode_f8time
		if mode_f8time = Error
			IniWrite, 0, config.ini, game, mode_f8time
		
		progressText("Чтение конфига: секция game, пункт supportresps")
		IniRead, supportresps, config.ini, game, supportresps
		if supportresps = Error
			IniWrite, 0, config.ini, game, supportresps
		
		progressText("Чтение конфига: секция game, пункт suphelper")
		IniRead, suphelper, config.ini, game, suphelper
		if suphelper = Error
			IniWrite, 0, config.ini, game, suphelper
		
		progressText("Чтение конфига: секция game, пункт Suphelper_WriteResponses")
		IniRead, Suphelper_WriteResponses, config.ini, game, Suphelper_WriteResponses
		if Suphelper_WriteResponses = Error
			IniWrite, 0, config.ini, game, Suphelper_WriteResponses
		
		ifnotexist, suphelper.ini
			FileAppend, `# Формат записи: 'вопрос' => 'ответ'`n# При сохранении файла убедитесь`, что последняя строка этого файла пустая.`n`n, suphelper.ini
		
		progressText("Чтение конфига: секция game, пункт supportresp_count")
		IniRead, supportresp_count, config.ini, game, supportresp_count
		if supportresp_count = Error
			IniWrite, 0, config.ini, game, supportresp_count
		
		; Начало автореестра
		
		IniRead, AutoregisterRankListArmy_MV, config.ini, autoregister, rankListArmy_MV
		if AutoregisterRankListArmy_MV = Error
			IniWrite, % "Рядовой,Ефрейтор,Мл.Сержант,Сержант,Ст.Сержант,Прапорщик,Ст.Прапорщик,Мл.Лейтенант,Лейтенант,Ст.Лейтенант,Капитан,Майор,Подполковник,Полковник,Генерал", config.ini, autoregister, rankListArmy_MV
		
		IniRead, AutoregisterRankListArmy_VMF, config.ini, autoregister, rankListArmy_VMF
		if AutoregisterRankListArmy_VMF = Error
			IniWrite, % "Матрос,Ст. Матрос,Старшина,Гл. Старшина,Боцман,Прапорщик,Мичман,Ст. Мичман,Мл. Лейтенант,Лейтенант,Ст. Лейтенант,Капитан,Контр-Адмирал,Вице-Адмирал,Адмирал", config.ini, autoregister, rankListArmy_VMF
		
		IniRead, AutoregisterRankListPolice_South, config.ini, autoregister, rankListPolice_South
		if AutoregisterRankListPolice_South = Error
			IniWrite, % "Кадет,Мл. Сержант,Сержант,Ст. Сержант,Прапорщик,Ст. Прапорщик,Мл. Лейтенант,Лейтенант,Ст. Лейтенант,Майор,Подполковник,Полковник,Генерал", config.ini, autoregister, rankListPolice_South
		
		IniRead, AutoregisterRankListPolice_Arzamas, config.ini, autoregister, rankListPolice_Arzamas
		if AutoregisterRankListPolice_Arzamas = Error
			IniWrite, % "Кадет,Мл. Сержант,Сержант,Ст. Сержант,Прапорщик,Ст. Прапорщик,Мл. Лейтенант,Лейтенант,Ст. Лейтенант,Майор,Подполковник,Полковник,Генерал", config.ini, autoregister, rankListPolice_Arzamas
		
		IniRead, AutoregisterRankListGIBDD, config.ini, autoregister, rankListGIBDD
		if AutoregisterRankListGIBDD = Error
			IniWrite, % "Кадет,Мл. Сержант,Сержант,Ст. Сержант,Прапорщик,Ст. Прапорщик,Мл. Лейтенант,Лейтенант,Ст. Лейтенант,Майор,Подполковник,Полковник,Генерал", config.ini, autoregister, rankListGIBDD
		
		IniRead, AutoregisterRankListAdmin_President, config.ini, autoregister, rankListAdmin_President
		if AutoregisterRankListAdmin_President = Error
			IniWrite, % "Охранник,Нач. Охраны,Секретарь,Адвокат,Судья,Министр связи,Министр финансов,Министр здравохранения,Министр обороны,Министр Внутренних Дел,Министр Финансов,Вице-Президент,Президент", config.ini, autoregister, rankListAdmin_President
		
		IniRead, AutoregisterRankListAdmin_Batirevo, config.ini, autoregister, rankListAdmin_Batirevo
		if AutoregisterRankListAdmin_Batirevo = Error
			IniWrite, % "Охранник,Нач. Охраны,Секретарь,Адвокат,Инспектор,Вице-Мэр,Мэр", config.ini, autoregister, rankListAdmin_Batirevo
		
		IniRead, AutoregisterRankListFBI, config.ini, autoregister, rankListFBI
		if AutoregisterRankListFBI = Error
			IniWrite, % "Мл.Лейтенант,Лейтенант,Ст.Лейтенант,Капитан,Подполковник,Полковник,Генерал-Полковник", config.ini, autoregister, rankListFBI
		
		IniRead, AutoregisterRankListSMI, config.ini, autoregister, rankListSMI
		if AutoregisterRankListSMI = Error
			IniWrite, % "Стажёр,Начинающий работник,Светотехник,Ведущий,Редактор,Гл. Редактор,Заместитель директора,Директор", config.ini, autoregister, rankListSMI
		
		IniRead, AutoregisterRankListInstructor, config.ini, autoregister, rankListInstructor
		if AutoregisterRankListInstructor = Error
			IniWrite, % "Стажёр,Консультант,Экзаменатор,Инструктор,Координатор,Менеджер,Заместитель директора,Директор", config.ini, autoregister, rankListInstructor
		
		IniRead, AutoregisterRankListCGB_South, config.ini, autoregister, rankListCGB_South
		if AutoregisterRankListCGB_South = Error
			IniWrite, % "Охранник,Интерн,Мед. брат,Врач терапевт,Врач инфекционист,Врач нарколог,Врач пульмонолог,Зам. Глав. врача,Глав. Врач", config.ini, autoregister, rankListCGB_South
		
		IniRead, AutoregisterRankListCGB_Arzamas, config.ini, autoregister, rankListCGB_Arzamas
		if AutoregisterRankListCGB_Arzamas = Error
			IniWrite, % "Охранник,Интерн,Мед. брат,Врач терапевт,Врач инфекционист,Врач нарколог,Врач пульмонолог,Зам. Глав. врача,Глав. Врач", config.ini, autoregister, rankListCGB_Arzamas
		
		progressText("Чтение конфига: секция autoregister, пункт state")
		IniRead, autoregister, config.ini, Autoregister, state
		if autoregister = Error
			IniWrite, 0, config.ini, Autoregister, state
		
		progressText("Чтение конфига: секция autoregister, пункт arimgur")
		IniRead, arimgur, config.ini, Autoregister, arimgur
		if arimgur = Error
			IniWrite, 1, config.ini, Autoregister, arimgur
		
		progressText("Чтение конфига: секция autoregister, пункт arsavescreens")
		IniRead, arsavescreens, config.ini, Autoregister, arsavescreens
		if arsavescreens = Error
			IniWrite, 1, config.ini, Autoregister, arsavescreens
		
		progressText("Чтение конфига: секция autoregister, пункт formatText")
		IniRead, AutoregisterFormatText, config.ini, Autoregister, formatText
		if AutoregisterFormatText = Error
			IniWrite, % "$name_$family | $day.$month.$year | $drank | $action | $reason | $mynick", config.ini, Autoregister, formatText
		
		progressText("Чтение конфига: секция RolePlay, пункт autogunrppkm")
		IniRead, autogunrppkm, config.ini, RolePlay, autogunrppkm
		if autogunrppkm = Error
			IniWrite, 0, config.ini, RolePlay, autogunrppkm
		
		progressText("Чтение конфига: секция roleplay, пункт armourrp")
		IniRead, armourrp, config.ini, roleplay, armourrp
		if armourrp = Error
			IniWrite, 1, config.ini, roleplay, armourrp
		
		progressText("Чтение конфига: секция roleplay, пункт rusnick")
		IniRead, rusnick, config.ini, Roleplay, rusnick
		if rusnick = Error
			IniWrite, % "", config.ini, RolePlay, rusnick
		
		progressText("Чтение конфига: секция roleplay, пункт fraction")
		IniRead, fraction, config.ini, Roleplay, fraction
		if fraction = Error
			IniWrite, % "", config.ini, RolePlay, fraction
		
		progressText("Чтение конфига: секция roleplay, пункт tag")
		IniRead, tag, config.ini, Roleplay, tag
		if tag = Error
			IniWrite, % "", config.ini, RolePlay, tag
		
		progressText("Чтение конфига: секция roleplay, пункт clist")
		IniRead, clist, config.ini, Roleplay, clist
		if clist = Error
			IniWrite, % "", config.ini, RolePlay, clist
		
		progressText("Чтение конфига: секция roleplay, пункт rang")
		IniRead, rang, config.ini, Roleplay, rang
		if rang = Error
			IniWrite, % "", config.ini, RolePlay, rang
		
		progressText("Чтение конфига: секция roleplay, пункт number")
		IniRead, number, config.ini, Roleplay, number
		if number = Error
			IniWrite, % "", config.ini, RolePlay, number
		
		progressText("Чтение конфига: секция vkauth, пункт token")
		IniRead, token, config.ini, vkauth, token
		if token = Error
			IniWrite, % "", config.ini, vkauth, token
		
		progressText("Чтение конфига: секция netcontrol, пункт VKAPI_Limit")
		IniRead, VKAPI_Limit, config.ini, netcontrol, VKAPI_Limit
		if VKAPI_Limit = Error
			IniWrite, % "86", config.ini, netcontrol, VKAPI_Limit
		
		; Отыгровки
		progressText("Чтение gunrp...")
		IfNotExist, gunrp.ini
		{
			fileappend, % "# Тут вы можете отредактировать отыгровку оружия, но в редакторе будет удобнее.`n# Секция ON отвечает за отыгровку, когда вы достаете оружие.`n# Секция OFF отвечает за отыгровку, когда вы прячете оружие.`n# Если Вы оставите пустую отыгровку, то ГГ будет смеятся.`n# Если Вы все-таки решили редактировать отыгровки тут, то не забудьте написать противоположную отыгровку (прятать, доставать оружие).`n# После редактирования рекомендуется открыть редактор, он сообщит об ошибках, если они имеются.`n`n", gunrp.ini
			IniWrite, % "/me потянулся(ась) за дубинкой и взял ее в руки|/do Дубинка в руках.", gunrp.ini, on, id3
			IniWrite, % "/me повесил(а) дубинку на поясный держатель|/do Дубинка на поясном держателе.", gunrp.ini, off, id3
			IniWrite, % "/me снял(а) электрошокер с пояса и держит его в руке|/do Электрошокер в боевой готовности.", gunrp.ini, on, id23
			IniWrite, % "/me закрепил(а) электрошокер на поясе|/do Электрошокер на поясе.", gunrp.ini, off, id23
			IniWrite, % "/me достал(а) Deagle из кобуры, после чего снял(а) с предохранителя|/do Deagle в боевой готовности.", gunrp.ini, on, id24
			IniWrite, % "/me поставил(а) Deagle на предохранитель и положил(а) в кобуру|/do Deagle в кобуре.", gunrp.ini, off, id24
			IniWrite, % "/me достал(а) дробовик из-за спины и снял(а) с предохранителя|/do Дробовик в боевой готовности.", gunrp.ini, on, id25
			IniWrite, % "/me поставил(а) дробовик на предохранитель и спрятал(а) за спиной|/do Дробовик за спиной.", gunrp.ini, off, id25
			IniWrite, % "/me достал(а) пистолет-пулемет из кобуры и снял(а) с предохранителя|/do Пистолет-пулемет в боевой готовности.", gunrp.ini, on, id29
			IniWrite, % "/me поставил(а) пистолет-пулемет на предохранитель и положил(а) в кобуру|/do Пистолет-пулемет в кобуре.", gunrp.ini, off, id29
			IniWrite, % "/me достал(а) M4 из-за спины и снял(а) с предохранителя|/do M4 в боевой готовности.", gunrp.ini, on, id31
			IniWrite, % "/me поставил(а) M4 на предохранитель и спрятал(а) за спиной|/do M4 за спиной.", gunrp.ini, off, id31
			IniWrite, % "/me достал(а) винтовку из-за спины и снял(а) с предохранителя|/do Винтовка в боевой готовости.", gunrp.ini, on, id33
			IniWrite, % "/me поставил(а) винтовку на предохранитель и спрятал(а) за спиной|/do Винтовка за спиной.", gunrp.ini, off, id33
		}
		
		progressText("Чтение конфига: секция overlay, пункт allow_support")
		IniRead, ov_allow_support, config.ini, overlay, allow_support
		if ov_allow_support = Error
			IniWrite, 1, config.ini, overlay, allow_support
		
		progressText("Чтение конфига: секция overlay, пункт showoverlay")
		IniRead, showoverlay, config.ini, overlay, showoverlay
		if showoverlay = Error
			IniWrite, 1, config.ini, overlay, showoverlay
		
		progressText("Чтение конфига: секция overlay, пункт ovx")
		IniRead, ovx, config.ini, overlay, ovx
		if ovx = Error
			IniWrite, 1, config.ini, overlay, ovx
		
		progressText("Чтение конфига: секция overlay, пункт ovy")
		IniRead, ovy, config.ini, overlay, ovy
		if ovy = Error
			IniWrite, 1, config.ini, overlay, ovy
		
		progressText("Чтение конфига: секция overlay, пункт ovfontname")
		IniRead, ovfontname, config.ini, overlay, ovfontname
		if ovfontname = Error
			IniWrite, Consolas, config.ini, overlay, ovfontname
		
		progressText("Чтение конфига: секция overlay, пункт ovsize")
		IniRead, ovsize, config.ini, overlay, ovsize
		if ovsize = Error
			IniWrite, 6, config.ini, overlay, ovsize
		
		progressText("Конфиг прочитан.")
	}
}

waitForSingleObject(hThread, dwMilliseconds) {
	if (!hThread) {
		ErrorLevel := ERROR_INVALID_HANDLE
		return 0
	}
	
	dwRet := DllCall("WaitForSingleObject", "UInt", hThread, "UInt", dwMilliseconds, "UInt")
	if (dwRet == 0xFFFFFFFF) {
		ErrorLEvel := ERROR_WAIT_FOR_OBJECT
		return 0
	}
	
	ErrorLevel := ERROR_OK
	return dwRet
}
createRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId) {
	if (!hProcess) {
		ErrorLevel := ERROR_INVALID_HANDLE
		return 0
	}
	
	dwRet := DllCall("CreateRemoteThread", "UInt", hProcess, "UInt", lpThreadAttributes, "UInt", dwStackSize, "UInt", lpStartAddress, "UInt", lpParameter, "UInt", dwCreationFlags, "UInt", lpThreadId, "UInt")
	if (dwRet == 0) {
		ErrorLEvel := ERROR_ALLOC_MEMORY
		return 0
	}
	
	ErrorLevel := ERROR_OK
	return dwRet
}
virtualFreeEx(hProcess, lpAddress, dwSize, dwFreeType) {
	if (!hProcess) {
		ErrorLevel := ERROR_INVALID_HANDLE
		return 0
	}
	
	dwRet := DllCall("VirtualFreeEx", "UInt", hProcess, "UInt", lpAddress, "UInt", dwSize, "UInt", dwFreeType, "UInt")
	if (dwRet == 0) {
		ErrorLEvel := ERROR_FREE_MEMORY
		return 0
	}
	ErrorLevel := ERROR_OK
	return dwRet
}
virtualAllocEx(hProcess, dwSize, flAllocationType, flProtect) {
	if (!hProcess) {
		ErrorLevel := ERROR_INVALID_HANDLE
		return 0
	}
	
	dwRet := DllCall("VirtualAllocEx", "UInt", hProcess, "UInt", 0, "UInt", dwSize, "UInt", flAllocationType, "UInt", flProtect, "UInt")
	if (dwRet == 0) {
		ErrorLEvel := ERROR_ALLOC_MEMORY
		return 0
	}
	
	ErrorLevel := ERROR_OK
	return dwRet
}
getDist(pos1,pos2) {
	if(!pos1 || !pos2)
		return 0
    return Sqrt((pos1[1]-pos2[1])*(pos1[1]-pos2[1])+(pos1[2]-pos2[2])*(pos1[2]-pos2[2])+(pos1[3]-pos2[3])*(pos1[3]-pos2[3]))
}
callWithParams(hProcess, dwFunc, aParams, bCleanupStack = true, thiscall = false) {
	if (!hProcess) {
		ErrorLevel := ERROR_INVALID_HANDLE
		return false
	}
	validParams := 0
	i := aParams.MaxIndex()
	dwLen := i * 5 + 5 + 1
	if (bCleanupStack)
		dwLen += 3
	VarSetCapacity(injectData, i * 5 + 5 + 3 + 1, 0)
	i_ := 1
	while(i > 0) {
		if (aParams[i][1] != "") {
			dwMemAddress := 0x0
			if (aParams[i][1] == "p") {
				dwMemAddress := aParams[i][2]
			} else if (aParams[i][1] == "s") {
				if (i_>3)
					return false
				dwMemAddress := pParam%i_%
				writeString(hProcess, dwMemAddress, aParams[i][2])
				if (ErrorLevel)
					return false
				i_ += 1
			} else if (aParams[i][1] == "i") {
				dwMemAddress := aParams[i][2]
			} else {
				return false
			}
			NumPut((thiscall && i == 1 ? 0xB9 : 0x68), injectData, validParams * 5, "UChar")
			NumPut(dwMemAddress, injectData, validParams * 5 + 1, "UInt")
			validParams += 1
		}
		i -= 1
	}
	offset := dwFunc - ( pInjectFunc + validParams * 5 + 5 )
	NumPut(0xE8, injectData, validParams * 5, "UChar")
	NumPut(offset, injectData, validParams * 5 + 1, "Int")
	if (bCleanupStack) {
		NumPut(0xC483, injectData, validParams * 5 + 5, "UShort")
		NumPut(validParams*4, injectData, validParams * 5 + 7, "UChar")
		NumPut(0xC3, injectData, validParams * 5 + 8, "UChar")
	} else {
		NumPut(0xC3, injectData, validParams * 5 + 5, "UChar")
	}
	writeRaw(hGTA, pInjectFunc, &injectData, dwLen)
	if (ErrorLevel)
		return false
	hThread := createRemoteThread(hGTA, 0, 0, pInjectFunc, 0, 0, 0)
	if (ErrorLevel)
		return false
	waitForSingleObject(hThread, 0xFFFFFFFF)
	closeProcess(hThread)
	return true
}
writeRaw(hProcess, dwAddress, pBuffer, dwLen) {
	if (!hProcess) {
		ErrorLevel := ERROR_INVALID_HANDLE
		return false
	}
	
	dwRet := DllCall("WriteProcessMemory", "UInt", hProcess, "UInt", dwAddress, "UInt", pBuffer, "UInt", dwLen, "UInt", 0, "UInt")
	if (dwRet == 0) {
		ErrorLEvel := ERROR_WRITE_MEMORY
		return false
	}
	
	ErrorLevel := ERROR_OK
	return true
}
writeString(hProcess, dwAddress, wString) {
	if (!hProcess) {
		ErrorLevel := ERROR_INVALID_HANDLE
		return false
	}
	
	sString := wString
	if (A_IsUnicode)
		sString := __unicodeToAnsi(wString)
	
	dwRet := DllCall("WriteProcessMemory", "UInt", hProcess, "UInt", dwAddress, "Str", sString, "UInt", StrLen(wString) + 1, "UInt", 0, "UInt")
	if (dwRet == 0) {
		ErrorLEvel := ERROR_WRITE_MEMORY
		return false
	}
	
	ErrorLevel := ERROR_OK
	return true
}
readMem(hProcess, dwAddress, dwLen=4, type="UInt") {
	if (!hProcess) {
		ErrorLevel := ERROR_INVALID_HANDLE
		return 0
	}
	
	VarSetCapacity(dwRead, dwLen)
	dwRet := DllCall("ReadProcessMemory", "UInt", hProcess, "UInt", dwAddress, "Str", dwRead, "UInt", dwLen, "UInt*", 0)
	if (dwRet == 0) {
		ErrorLevel := ERROR_READ_MEMORY
		return 0
	}
	
	ErrorLevel := ERROR_OK
	return NumGet(dwRead, 0, type)
}
readDWORD(hProcess, dwAddress) {
	if (!hProcess) {
		ErrorLevel := ERROR_INVALID_HANDLE
		return 0
	}
	
	VarSetCapacity(dwRead, 4)	; DWORD = 4
	dwRet := DllCall("ReadProcessMemory", "UInt", hProcess, "UInt", dwAddress, "Str", dwRead, "UInt", 4, "UInt*", 0)
	if (dwRet == 0) {
		ErrorLevel := ERROR_READ_MEMORY
		return 0
	}
	
	ErrorLevel := ERROR_OK
	return NumGet(dwRead, 0, "UInt")
}
readFloat(hProcess, dwAddress) {
	if (!hProcess) {
		ErrorLevel := ERROR_INVALID_HANDLE
		return 0
	}
	
	VarSetCapacity(dwRead, 4)	; float = 4
	dwRet := DllCall("ReadProcessMemory", "UInt", hProcess, "UInt", dwAddress, "Str", dwRead, "UInt", 4, "UInt*", 0, "UInt")
	if (dwRet == 0) {
		ErrorLevel := ERROR_READ_MEMORY
		return 0
	}
	
	ErrorLevel := ERROR_OK
	return NumGet(dwRead, 0, "Float")
}
readString(hProcess, dwAddress, dwLen) {
	if (!hProcess) {
		ErrorLevel := ERROR_INVALID_HANDLE
		return 0
	}
	
	VarSetCapacity(sRead, dwLen)
	dwRet := DllCall("ReadProcessMemory", "UInt", hProcess, "UInt", dwAddress, "Str", sRead, "UInt", dwLen, "UInt*", 0, "UInt")
	if (dwRet == 0) {
		ErrorLevel := ERROR_READ_MEMORY
		return 0
	}
	
	ErrorLevel := ERROR_OK
	if A_IsUnicode
		return __ansiToUnicode(sRead)
	return sRead
}

getModuleBaseAddress(sModule, hProcess) {
	if (!sModule) {
		ErrorLevel := ERROR_MODULE_NOT_FOUND
		return 0
	}
	
	if (!hProcess) {
		ErrorLevel := ERROR_INVALID_HANDLE
		return 0
	}
	
	dwSize = 1024*4					; 1024 * sizeof(HMODULE = 4)
	VarSetCapacity(hMods, dwSize)	
	VarSetCapacity(cbNeeded, 4)		; DWORD = 4
	dwRet := DllCall("Psapi.dll\EnumProcessModules", "UInt", hProcess, "UInt", &hMods, "UInt", dwSize, "UInt*", cbNeeded, "UInt")
	if (dwRet == 0) {
		ErrorLevel := ERROR_ENUM_PROCESS_MODULES
		return 0
	}
	
	dwMods := cbNeeded / 4			; cbNeeded / sizeof(HMDOULE = 4)
	i := 0
	VarSetCapacity(hModule, 4)		; HMODULE = 4
	VarSetCapacity(sCurModule, 260)	; MAX_PATH = 260
	while(i < dwMods) {
		hModule := NumGet(hMods, i*4)
		DllCall("Psapi.dll\GetModuleFileNameEx", 	"UInt", hProcess, 	"UInt", hModule, 	"Str", sCurModule, 	"UInt", 260)
		SplitPath, sCurModule, sFilename
		if (sModule == sFilename) {
			ErrorLevel := ERROR_OK
			return hModule
		}
		i := i + 1
	}
	
	ErrorLevel := ERROR_MODULE_NOT_FOUND
	return 0
}
closeProcess(hProcess) {
	if (hProcess == 0) {
		ErrorLevel := ERROR_INVALID_HANDLE
		return 0
	}
	
	dwRet := DllCall("CloseHandle", "Uint", hProcess, "UInt")
	ErrorLevel := ERROR_OK
}
openProcess(dwPID, dwRights = 0x1F0FFF) {
	hProcess := DllCall("OpenProcess", "UInt", dwRights, "int",  0, "UInt", dwPID, "Uint")
	if (hProcess == 0) {
		ErrorLevel := ERROR_OPEN_PROCESS
		return 0
	}
	
	ErrorLevel := ERROR_OK
	return hProcess
}
getPID() {
	local dwPID := 0
	WinGet, dwPID, PID, GTA:SA:MP
	return dwPID
}
refreshMemory() {
	if (!pMemory) {
		pMemory	 := virtualAllocEx(hGTA, 6144, 0x1000 | 0x2000, 0x40)
		if (ErrorLevel) {
			pMemory := 0x0
			return false
		}
		pParam1	:= pMemory
		pParam2	:= pMemory + 1024
		pParam3 := pMemory + 2048
		pParam4	:= pMemory + 3072
		pParam5	:= pMemory + 4096
		pInjectFunc := pMemory + 5120
	}
	return true
}
refreshSAMP() {
	if (dwSAMP)
		return true
	
	dwSAMP := getModuleBaseAddress("samp.dll", hGTA)
	if (!dwSAMP) return false
	
	return true
}
refreshGTA() {
	newPID := getPID()
	if (!newPID) {							; GTA not found
		if (hGTA) {							; open handle
			virtualFreeEx(hGTA, pMemory, 0, 0x8000)
			closeProcess(hGTA)
			hGTA := 0x0
		}
		dwGTAPID := 0
		hGTA := 0x0
		dwSAMP := 0x0
		pMemory := 0x0
		return false
	}
	
	if (!hGTA || (dwGTAPID != newPID)) {		; changed PID, closed handle
		hGTA := openProcess(newPID)
		if (ErrorLevel) {					; openProcess fail
			dwGTAPID := 0
			hGTA := 0x0
			dwSAMP := 0x0
			pMemory := 0x0
			return false
		}
		dwGTAPID := newPID
		dwSAMP := 0x0
		pMemory := 0x0
		return true
	}
	return true
}
checkHandles() {
	if (iRefreshHandles+500>A_TickCount)
		return true
	
	iRefreshHandles:=A_TickCoun
	dwSAMP := getModuleBaseAddress("samp.dll", hGTA)
	return (refreshGTA() && refreshSAMP() && refreshMemory())
}
writeMemory(hProcess, address, writevalue,length=4, datatype="int") {
	if (!hProcess) {
		ErrorLevel := ERROR_INVALID_HANDLE
		return false
	}

	VarSetCapacity(finalvalue,length, 0)
	NumPut(writevalue,finalvalue,0,datatype)
	dwRet := DllCall("WriteProcessMemory", "Uint", hProcess, "Uint", address, "Uint", &finalvalue, "Uint", length, "Uint", 0)
	if (dwRet == 0) {
		ErrorLevel := ERROR_WRITE_MEMORY
		return false
	}
	ErrorLevel := ERROR_OK
	return true
}
writeByte(hProcess, dwAddress, wInt) {
	if (!hProcess) {
		ErrorLevel := ERROR_INVALID_HANDLE
		return false
	}
	wInt := IntToHex(wInt)
	dwRet := DllCall("WriteProcessMemory", "UInt", hProcess, "UInt", dwAddress, "UInt *", wInt, "UInt", 1, "UInt *", 0)
}
FloatToHex(value) {
   format := A_FormatInteger
   SetFormat, Integer, H
   result := DllCall("MulDiv", Float, value, Int, 1, Int, 1, UInt)
   SetFormat, Integer, %format%
   return, result
}

IntToHex(int) {
	CurrentFormat := A_FormatInteger
	SetFormat, integer, hex
	int += 0
	SetFormat, integer, %CurrentFormat%
	return int
}
writeFloat(hProcess, dwAddress, wFloat) {
	if (!hProcess) {
		ErrorLevel := ERROR_INVALID_HANDLE
		return false
	}
	wFloat := FloatToHex(wFloat)
	dwRet := DllCall("WriteProcessMemory", "UInt", hProcess, "UInt", dwAddress, "UInt *", wFloat, "UInt", 4, "UInt *", 0)
	ErrorLevel := ERROR_OK
	return true
}
HexToDec(str) {   
	local newStr := ""
	static comp := {0:0, 1:1, 2:2, 3:3, 4:4, 5:5, 6:6, 7:7, 8:8, 9:9, "a":10, "b":11, "c":12, "d":13, "e":14, "f":15}
	str := RegExReplace(str.down(str), "^0x|[^a-f0-9]+", "")
	Loop, % StrLen(str)
		newStr .= SubStr(str, (StrLen(str)-A_Index)+1, 1)
	newStr := StrSplit(newStr, "")
	local ret := 0
	for i,char in newStr
		ret += comp[char]*(16**(i-1))
	return ret
}
HexToDecOne(Hex) {
	if (InStr(Hex, "0x") != 1)
	Hex := "0x" Hex
	return, Hex + 0
}
HexToDecTwo(hex) {
	VarSetCapacity(dec, 66, 0), 
	val := DllCall("msvcrt.dll\_wcstoui64", "Str", hex, "UInt", 0, "UInt", 16, "CDECL Int64"), DllCall("msvcrt.dll\_i64tow", "Int64", val, "Str", dec, "UInt", 10, "CDECL")
	return dec
}
hex2rgb(CR) {
	NumPut((InStr(CR, "#") ? "0x" SubStr(CR, 2) : "0x") SubStr(CR, -5), (V := "000000"))
	return NumGet(V, 2, "UChar") "," NumGet(V, 1, "UChar") "," NumGet(V, 0, "UChar")
}
rgb2hex(R, G, B, H := 1) {
	static U := A_IsUnicode ? "_wcstoui64" : "_strtoui64"
	static V := A_IsUnicode ? "_i64tow"	: "_i64toa"
	rgb := ((R << 16) + (G << 8) + B)
	H := ((H = 1) ? "#" : ((H = 2) ? "0x" : ""))
	VarSetCapacity(S, 66, 0)
	value := DllCall("msvcrt.dll\" U, "Str", rgb , "UInt", 0, "UInt", 10, "CDECL Int64")
	DllCall("msvcrt.dll\" V, "Int64", value, "Str", S, "UInt", 16, "CDECL")
	return H S
}
writeBytes(handle, address, bytes) {
	length := strlen(bytes) / 2
	VarSetCapacity(toInject, length, 0)
	Loop %length% {
		byte := "0x" substr(bytes, ((A_Index - 1) * 2) + 1, 2)
		NumPut(byte, toInject, A_Index - 1, "uchar")
	}
	return writeRaw(handle, address, &toInject, length)
}
__ansiToUnicode(sString, nLen = 0) {
	if (!nLen) {
		nLen := DllCall("MultiByteToWideChar", "Uint", 0, "Uint", 0, "Uint", &sString, "int",  -1, "Uint", 0, "int",  0)
	}
	VarSetCapacity(wString, nLen * 2)
	DllCall("MultiByteToWideChar", "Uint", 0, "Uint", 0, "Uint", &sString, "int",  -1, "Uint", &wString, "int",  nLen)
	return wString
}
__unicodeToAnsi(wString, nLen = 0) {
	pString := wString + 1 > 65536 ? wString : &wString
	if (!nLen) {
		nLen := DllCall("WideCharToMultiByte", "Uint", 0, "Uint", 0, "Uint", pString, "int",  -1, "Uint", 0, "int",  0, "Uint", 0, "Uint", 0)
	}
	VarSetCapacity(sString, nLen)
	DllCall("WideCharToMultiByte", "Uint", 0, "Uint", 0, "Uint", pString, "int",  -1, "str",  sString, "int",  nLen, "Uint", 0, "Uint", 0)
	return sString
}
Utf8ToAnsi(ByRef Utf8String, CodePage = 1251) {
	if ((NumGet(Utf8String) & 0xFFFFFF) = 0xBFBBEF)
		BOM = 3
	else
		BOM = 0
	UniSize := DllCall("MultiByteToWideChar", "UInt", 65001, "UInt", 0, "UInt", &Utf8String + BOM, "Int", -1, "Int", 0, "Int", 0)
	VarSetCapacity(UniBuf, UniSize * 2)
	DllCall("MultiByteToWideChar", "UInt", 65001, "UInt", 0, "UInt", &Utf8String + BOM, "Int", -1, "UInt", &UniBuf, "Int", UniSize)
	AnsiSize := DllCall("WideCharToMultiByte", "UInt", CodePage, "UInt", 0, "UInt", &UniBuf, "Int", -1, "Int", 0, "Int", 0, "Int", 0, "Int", 0)
	VarSetCapacity(AnsiString, AnsiSize)
	DllCall("WideCharToMultiByte", "UInt", CodePage, "UInt", 0, "UInt", &UniBuf, "Int", -1, "Str", AnsiString, "Int", AnsiSize, "Int", 0, "Int", 0)
	return AnsiString
}

setGravity(state="0.008") {
	if (!checkHandles())
		return -1
	
	return writeFloat(hGTA, 0x863984, state)
}

setCoordinates(pos1, pos2, pos3) {
	if (!checkHandles())
		return -1

	dwAddress := isPlayerInAnyVehicle()
	if (dwAddress == 0)
		dwAddress := readDWORD(hGTA, 0xB6F5F0)
	dwAddress := readDWORD(hGTA, dwAddress + 0x14)
	
	writeFloat(hGTA, dwAddress + 0x30, pos1)
	writeFloat(hGTA, dwAddress + 0x34, pos2)
	writeFloat(hGTA, dwAddress + 0x38, pos3)
	
	return true
}

getPlayerHealth() {
	if (!checkHandles())
		return -1
		
	return readFloat(hGTA, readDWORD(hGTA, 0xB6F5F0) + 0x540)
}
getPlayerArmour() {
	if (!checkHandles())
		return -1
		
	return readFloat(hGTA, readDWORD(hGTA, 0xB6F5F0) + 0x548)
}
getPlayerMoney() {
	if (!checkHandles())
		return -1
		
	return readDWORD(hGTA, 0x0B7CE54)
}
getPlayerInteriorId() {
	if (!checkHandles())
		return -1
		
	return readDWORD(hGTA, 0xA4ACE8)
}
getPlayerSkinId() {
	if (!checkHandles())
		return -1
		
	return readMem(hGTA, readDWORD(hGTA, 0xB6F5F0) + 0x22, 2, "byte")
}
getPlayerWeaponId() {
	if (!checkHandles())
		return -1
		
	return readDWORD(hGTA, 0xBAA410)
}

checkCRMP() {
	IfWinNotActive, ahk_exe gta_sa.exe
		return 0
	
	return 1
}

; Функции чтения, связанные с текущим транспортом
isPlayerInAnyVehicle() {
	if (!checkHandles())
		return -1
		
	return readDWORD(hGTA, 0xBA18FC)
}
getVehicleHealth() {
	if (!checkHandles())
		return -1
		
	return readFloat(hGTA, readDWORD(hGTA, 0xBA18FC) + 0x4C0)
}
isPlayerDriver() {
	if (!checkHandles())
		return -1
		
	return (readDWORD(hGTA, readDWORD(hGTA, 0xBA18FC) + 0x460) == readDWORD(hGTA, 0xB6F5F0))
}
getVehicleColor() {
	if (!checkHandles())
		return -1
		
	dwAddress := isPlayerInAnyVehicle()
	return [readMem(hGTA, dwAddress + 1076, 1, "byte"), readMem(hGTA, dwAddress + 1077, 1, "byte")]
}
getVehicleSpeed() {
	if(!checkHandles())
		return -1
 
	dwAddress := isPlayerInAnyVehicle()
	
	fSpeedX := readMem(hGTA, dwAddress + 0x44, 4, "float")
	fSpeedY := readMem(hGTA, dwAddress + 0x48, 4, "float")
	fSpeedZ := readMem(hGTA, dwAddress + 0x4C, 4, "float")
	
	fVehicleSpeed := sqrt((fSpeedX * fSpeedX) + (fSpeedY * fSpeedY) + (fSpeedZ * fSpeedZ))
	fVehicleSpeed := (fVehicleSpeed * 100) * 1.43
 
	return Round(fVehicleSpeed)
}

; Функции, связанные с координатами
getCoordinates(ByRef x, ByRef y, ByRef z) {
	if (!checkHandles())
		return -1
		
	dwAddress := isPlayerInAnyVehicle()
	if (dwAddress == 0)
		dwAddress := readDWORD(hGTA, 0xB6F5F0)
	dwAddress := readDWORD(hGTA, dwAddress + 0x14)
	
	x := readFloat(hGTA, dwAddress + 0x30)
	z := readFloat(hGTA, dwAddress + 0x34)
	y := readFloat(hGTA, dwAddress + 0x38)
}
getPlayerCoordinates(ByRef x, ByRef y, ByRef z) {
	if (!checkHandles())
		return -1
		
	dwAddress := readDWORD(hGTA, readDWORD(hGTA, 0xB6F5F0) + 0x14)
	
	x := readFloat(hGTA, dwAddress + 0x30)
	z := readFloat(hGTA, dwAddress + 0x34)
	y := readFloat(hGTA, dwAddress + 0x38)
}
getCameraCoordinates(ByRef x, ByRef y, ByRef z) {
	if (!checkHandles())
		return -1
	
	x := readFloat(hGTA, 0xB6F9CC)
	y := readFloat(hGTA, 0xB6F9D4)
	z := readFloat(hGTA, 0xB6F9D0)
}

; Функции, связанные с модулем мультиплеера
addChatMessageEx(Color, Text) {
	if (!checkHandles())
		return -1
   
	VarSetCapacity(data2, 4, 0)
	NumPut(HexToDec(Color), data2, 0, "Int")
	
	dwAddress := readDWORD(hGTA, dwSAMP + 0x26E8C8)
	VarSetCapacity(data1, 4, 0)
	NumPut(readDWORD(hGTA, dwAddress + 0x4), data1, 0, "Int") 
	WriteRaw(hGTA, dwAddress + 0x4, &data2, 4)
   
	callWithParams(hGTA, dwSAMP + 0x67970, [["p", readDWORD(hGTA, dwSAMP + 0x26E8C8)], ["s", "" Text]], true)
	WriteRaw(hGTA, dwAddress + 0x4, &data1, 4)
}

sendChat(Text) {	
	if (!checkHandles())
		return -1
	
	dwFunc := 0
	if (SubStr(Text, 1, 1) == "/") {
		dwFunc := dwSAMP + 0x69190
	} else {
		dwFunc := dwSAMP + 0x5820
	}
	
	callWithParams(hGTA, dwFunc, [["s", "" Text]], false)
}

isInChat() {	
	if (!checkHandles())
		return -1
	
	return (readDWORD(hGTA, readDWORD(hGTA, dwSAMP + 0x26E8F4) + 0x61) > 0)
}

class dialog {
	standard(text) {
		StringReplace, text, text, `%r, `{FF6347`}, All
		StringReplace, text, text, `\n, `n, All
		StringReplace, text, text, `\r, `r, All
		StringReplace, text, text, `\t, `t, All
		showdialog(0, "{4169E1}" title, "{FFFFFF}" text, "Закрыть")
	}
	list(text) {
		StringReplace, text, text, `\n, `n, All
		StringReplace, text, text, `\r, `r, All
		StringReplace, text, text, `\t, `t, All
		showdialog(5, "{4169E1}" title, text, "Закрыть")
	}
}

formatDialog(text, len=150) {
	result := "", index := 0
	loop, parse, text, % ""
	{
		index++
		if A_LoopField = `n
			index = 0
		
		result := result A_LoopField
		if (index = len) {
			result := result "`n"
			index = 0
		}
	}
	return result
}

showDialog(style, caption, text, button1, button2 := "", id := 1) {
	style += 0
	style := Floor(style)
	id += 0
	id := Floor(id)
	caption := "" caption
	text := "" text
	button1 := "" button1
	button2 := "" button2
	text := formatdialog(text)
	
	if (id < 0 || id > 32767 || style < 0 || style > 5 || StrLen(caption) > 64 || StrLen(text) > 4096 || StrLen(button1) > 10 || StrLen(button2) > 10)
		return false

	if (!checkHandles())
		return -1

	dwFunc := dwSAMP + 0x6F8C0
	sleep 200
	dwAddress := readDWORD(hGTA, dwSAMP + 0x26E898)
	if (!dwAddress) {
		return -1
	}

	writeString(hGTA, pParam5, caption)
	writeString(hGTA, pParam1, text)
	writeString(hGTA, pParam5 + 512, button1)
	writeString(hGTA, pParam5+StrLen(caption) + 1, button2)

	dwLen := 5 + 7 * 5 + 5 + 1
	VarSetCapacity(injectData, dwLen, 0)

	NumPut(0xB9, injectData, 0, "UChar")
	NumPut(dwAddress, injectData, 1, "UInt")
	NumPut(0x68, injectData, 5, "UChar")
	NumPut(1, injectData, 6, "UInt")
	NumPut(0x68, injectData, 10, "UChar")
	NumPut(pParam5 + StrLen(caption) + 1, injectData, 11, "UInt")
	NumPut(0x68, injectData, 15, "UChar")
	NumPut(pParam5 + 512, injectData, 16, "UInt")
	NumPut(0x68, injectData, 20, "UChar")
	NumPut(pParam1, injectData, 21, "UInt")
	NumPut(0x68, injectData, 25, "UChar")
	NumPut(pParam5, injectData, 26, "UInt")
	NumPut(0x68, injectData, 30, "UChar")
	NumPut(style, injectData, 31, "UInt")
	NumPut(0x68, injectData, 35, "UChar")
	NumPut(id, injectData, 36, "UInt")
	NumPut(0xE8, injectData, 40, "UChar")
	offset := dwFunc - (pInjectFunc + 45)
	NumPut(offset, injectData, 41, "Int")
	NumPut(0xC3, injectData, 45, "UChar")

	writeRaw(hGTA, pInjectFunc, &injectData, dwLen)
	hThread := createRemoteThread(hGTA, 0, 0, pInjectFunc, 0, 0, 0)

	;waitForSingleObject(hThread, 0xFFFFFFFF)
	closeProcess(hThread)
}

IsPlayerInRangeOfPoint(_posX, _posY, _posZ, _posRadius)
{
	getPlayerCoordinates(posX, posY, posZ)
	X := posX -_posX
	Y := posY -_posY
	Z := posZ -_posZ
	if(((X < _posRadius) && (X > -_posRadius)) && ((Y < _posRadius) && (Y > -_posRadius)) && ((Z < _posRadius) && (Z > -_posRadius)))
		return TRUE
	return FALSE
}

setFireImmunity(state)
{
    if(!checkHandles())
        return
    writeMemory(hGTA, 0xB7CEE6, (state ? 1 : 0), 1, "byte")
}

gmpatch()
{
    if(!checkHandles())
        return false
    a := writeMemory(hGTA, 0x4B35A0, 0x560CEC83, 4, "int")
    b := writeMemory(hGTA, 0x4B35A4, 0xF18B, 2, "byte")
    return (a && b)
}

toggleNoDamageByWeapon(tog := -1)
{
    if(!checkHandles())
        return -1
    byte := readMem(hGTA, 0x60A5BA, 1, "byte")
    if((tog == -1 && byte == 216) || tog == true || tog == 1)
    {
        writeBytes(hGTA, 0x60A5BA, "909090")
        return true
    } else if((tog == -1 && byte == 144) || !tog)
    {
        writeBytes(hGTA, 0x60A5BA, "D95E18")
        return false
    }
    addChatMessageEx(0xCC0000, "only for gta_sa.exe 1.0 us")
    return -1
}

toggleInvulnerability(tog := -1)
{
    if(!checkHandles())
        return -1
    byte := readMem(hGTA, 0x60A5BA, 1, "byte")
    if((tog == -1 && byte == 217) || tog == true || tog == 1)
    {
        writeBytes(hGTA, 0x4B3314, "909090")
        return true
    } else if((tog == -1 && byte == 144) || !tog)
    {
        writeBytes(hGTA, 0x4B3314, "D86504")
        return false
    }
    addChatMessageEx(0xCC0000, "only for gta_sa.exe 1.0 us")
    return -1
}

getDialogCaption() {
	if (!CheckHandles())
		return -1
	
	return readString(hGTA, dwSamp + 0x16e04aee, 512)
}

getDialogText() {
	if (!CheckHandles())
		return -1
	
	return readString(hGTA, dwSamp + 0x2069a38, 512)
}

AntiPause() {
    if(!checkHandles())
        return false
    writeBytes(hGTA, 0x747FB6, "01")
    writeBytes(hGTA, 0x74805A, "01")
    writeBytes(hGTA, 0x74542B, "90909090909090")
    writeBytes(hGTA, 0x74542C, "90909090909090")
    writeBytes(hGTA, 0x74542D, "909090909090")
    return
}

GetChatLine(Line, timestamp=0, color=0){
	FileRead, file, % path_chatlog
	chatindex := 0
	loop, Parse, file, `n, `r
	{
		if(A_LoopField)
			chatindex := A_Index
	}
	
	loop, Parse, file, `n, `r
	{
		if(A_Index = chatindex - line){
			output := A_LoopField
			break
		}
	}
	
	file := ""
	if(!timestamp)
		output := RegExReplace(output, "U)^\[\d{2}:\d{2}:\d{2}\]")
	if(!color)
		output := RegExReplace(output, "Ui)\{[a-f0-9]{6}\}")
	
	return output
}

UnlockFps(status) {
    if(!checkHandles())
        return false
    if (status = 1) {
  dwSAMP := getModuleBaseAddress("samp.dll", hGTA)
  writeMemory(hGTA, dwSAMP + 0x9D9D0, 1347550997, 4, "UInt")
    }
    if (status = 0) {
  dwSAMP := getModuleBaseAddress("samp.dll", hGTA)
  writeMemory(hGTA, dwSAMP + 0x9D9D0, 4294417384, 4, "UInt")
    }
    return
}

setInfiniteRun(state)
{
    if(!checkHandles())
        return
    writeMemory(hGTA, 0xB7CEE4, (state ? 1 : 0), 1, "byte")
}

PauseGame(state="") ; 0 - leave, 1 - shows
{
    if(!checkHandles())
        return
    
	if (state = "") {
		return readMem(hGTA, 0xB7CB49, 1, "byte")
	}
	
	return writeMemory(hGTA, 0xB7CB49, (state ? 1 : 0), 1, "byte")
}

PrintLow(text, time) {
    ;0x69F1E0 = PrintLowPriorityMessage(const char* text, int time_in_ms, int unknown1 = 1, int unknown2 = 1);
    if(!checkHandles())
        return -1
    dwFunc := 0x69F1E0
    callwithparams(hGta, dwFunc, [["s",text], ["i", time], ["i", 1], ["i", 1]], true)
}

setCarNitro() {
    If(!checkHandles())
        return -1
    return writeMemory(hGTA, 0x969165, 0x1)
}

toggleMotionBlur(tog := -1)
{
    if(!checkHandles())
        return -1
    byte := readMem(hGTA, 0x704E8A, 1, "byte")
    if((tog == -1 && byte == 144) || tog == true || tog == 1)
    {
        writeBytes(hGTA, 0x704E8A, "E811E2FFFF")
        return true
    } else if((tog == -1 && byte == 232) || !tog)
    {
        writeBytes(hGTA, 0x704E8A, "9090909090")
        return false
    }
    return -1
}

setTime(hour)
{
	if(!checkHandles())
		return
	; disable gta setTime function
	VarSetCapacity(nop, 6, 0)
	Loop 6 {
		NumPut(0x90, nop, A_INDEX-1, "UChar")
	}
	writeRaw(hGTA, 0x52D168, &nop, 6)

	; set our own weather
	VarSetCapacity(time, 1, 0)
	NumPut(hour, time, 0, "Int")
	writeRaw(hGTA, 0xB70153, &time, 1)
}

getWeatherID() {
    if(!checkHandles())
        return -1
    
    dwGTA := getModuleBaseAddress("gta_sa.exe", hGTA)
    WeatherID := readMem(hGTA, 0xC81320, 2, "byte")
    if(ErrorLevel) {
        ErrorLevel := ERROR_READ_MEMORY
        return -1
    }
    
    ErrorLevel := ERROR_OK    
    return WeatherID
}

setWeather(id)
{
	if(!checkHandles())
		return
	VarSetCapacity(weather, 1, 0)
	NumPut(id, weather, 0, "Int")
	writeRaw(hGTA, 0xC81320, &weather, 1)
	if(ErrorLevel)
		return false
	
	return true
}

setPlayerFreeze(status) {
    if(!checkHandles())
        return -1
    
    dwCPed := readDWORD(hGTA, 0xB6F5F0)
    if(ErrorLevel) {
        ErrorLevel := ERROR_READ_MEMORY
        return -1
    }
    dwAddr := dwCPed + 0x42 
	writeString(hGTA, dwAddr, status)
	if(ErrorLevel) {
		ErrorLevel := ERROR_WRITE_MEMORY
		return -1		
	}     
    ErrorLevel := ERROR_OK
    return true
}

IsPlayerFreezed() {
    if(!checkHandles())
        return -1
    
    dwGTA := getModuleBaseAddress("gta_sa.exe", hGTA)
    IPF := readMem(hGTA, dwGTA + 0x690495, 2, "byte")    
    if(ErrorLevel) {
        ErrorLevel := ERROR_READ_MEMORY
        return -1
    }
    
    ErrorLevel := ERROR_OK    
    return IPF
}

IsInAfk() {
	res := readMem(hGTA, 0xBA6748 + 0x5C)
	WinGet, win, MinMax, ahk_exe gta_sa.exe
	if ((res=0) and (win=-1)) or res=1
		return 1
	
	return 0
}

setPlayerHealth(amount) {
    if(!checkHandles())
        return -1
   
    dwCPedPtr := readDWORD(hGTA, ADDR_CPED_PTR)
    if(ErrorLevel) {
        ErrorLevel := ERROR_READ_MEMORY
        return -1
    }
   
    dwAddr := dwCPedPtr + ADDR_CPED_HPOFF
    writeFloat(hGTA, dwAddr, amount)
    if(ErrorLevel) {
        ErrorLevel := ERROR_READ_MEMORY
        return -1
    }
   
    ErrorLevel := ERROR_OK
    return true
}

setPlayerArmor(amount) {
    if(!checkHandles())
        return -1
   
    dwCPedPtr := readDWORD(hGTA, ADDR_CPED_PTR)
    if(ErrorLevel) {
        ErrorLevel := ERROR_READ_MEMORY
        return -1
    }
   
    dwAddr := dwCPedPtr + ADDR_CPED_ARMOROFF
    writeFloat(hGTA, dwAddr, amount)
    if(ErrorLevel) {
        ErrorLevel := ERROR_READ_MEMORY
        return -1
    }
   
    ErrorLevel := ERROR_OK
    return true
}

setVehicleHealth(amount) {
    if(!checkHandles())
        return -1
   
    dwVehPtr := readDWORD(hGTA, ADDR_VEHICLE_PTR)
    if(ErrorLevel) {
        ErrorLevel := ERROR_READ_MEMORY
        return -1
    }
   
    dwAddr := dwVehPtr + ADDR_VEHICLE_HPOFF
    writeFloat(hGTA, dwAddr, amount)
    if(ErrorLevel) {
        ErrorLevel := ERROR_READ_MEMORY
        return -1
    }
   
    ErrorLevel := ERROR_OK
    return true
}

class sampCfg
{
	fpslimit() {
		loop, read, % path_cfg
		{
			RegExMatch(A_LoopReadLine, "fpslimit=(.*)", out)
			if out1
				return out1
		}
	}
	
	multicore() {
		loop, read, % path_cfg
		{
			RegExMatch(A_LoopReadLine, "multicore=(.*)", out)
			if out1
				return out1
		}
	}
	
	audioproxyoff() {
		loop, read, % path_cfg
		{
			RegExMatch(A_LoopReadLine, "audioproxyoff=(.*)", out)
			if out1
				return out1
		}
	}
	
	pagesize() {
		loop, read, % path_cfg
		{
			RegExMatch(A_LoopReadLine, "pagesize=(.*)", out)
			if out1
				return out1
		}
	}
	
	fontsize() {
		loop, read, % path_cfg
		{
			RegExMatch(A_LoopReadLine, "fontsize=(.*)", out)
			if out1
				return out1
		}
	}
	
	timestamp() {
		loop, read, % path_cfg
		{
			RegExMatch(A_LoopReadLine, "timestamp=(.*)", out)
			if out1
				return out1
		}
	}
	
	disableheadmove() {
		loop, read, % path_cfg
		{
			RegExMatch(A_LoopReadLine, "disableheadmove=(.*)", out)
			if out1
				return out1
		}
	}
}

GetInputLangID(window)  {
   if !hWnd := WinExist(window)
      return

   WinGetClass, winClass
   if (winClass != "ConsoleWindowClass") || (b := SubStr(A_OSVersion, 1, 2) = "10")  {
      if b  {
         WinGet, consolePID, PID
         childConhostPID := GetCmdChildConhostPID(consolePID)
         dhw_prev := A_DetectHiddenWindows
         DetectHiddenWindows, On
         hWnd := WinExist("ahk_pid " . childConhostPID)
         DetectHiddenWindows, % dhw_prev
      }
      threadId := DllCall("GetWindowThreadProcessId", Ptr, hWnd, UInt, 0)
      lyt := DllCall("GetKeyboardLayout", Ptr, threadId, UInt)
      langID := Format("{:#x}", lyt & 0x3FFF)
   }
   else  {
      WinGet, consolePID, PID
      DllCall("AttachConsole", Ptr, consolePID)
      VarSetCapacity(lyt, 16)
      DllCall("GetConsoleKeyboardLayoutName", Str, lyt)
      DllCall("FreeConsole")
      langID := "0x" . SubStr(lyt, -4)
   }
   return langID
}

GetCmdChildConhostPID(CmdPID)  {
   static TH32CS_SNAPPROCESS := 0x2, MAX_PATH := 260
   
   h := DllCall("CreateToolhelp32Snapshot", UInt, TH32CS_SNAPPROCESS, UInt, 0, Ptr)
   VarSetCapacity(PROCESSENTRY32, size := 4*7 + A_PtrSize*2 + (MAX_PATH << !!A_IsUnicode), 0)
   NumPut(size, PROCESSENTRY32, "UInt")
   res := DllCall("Process32First", Ptr, h, Ptr, &PROCESSENTRY32)
   while res  {
      parentPid := NumGet(PROCESSENTRY32, 4*4 + A_PtrSize*2, "UInt")
      if (parentPid = CmdPID)  {
         exeName := StrGet(&PROCESSENTRY32 + 4*7 + A_PtrSize*2, "CP0")
         if (exeName = "conhost.exe" && PID := NumGet(PROCESSENTRY32, 4*2, "UInt"))
            break
      }
      res := DllCall("Process32Next", Ptr, h, Ptr, &PROCESSENTRY32)
   }
   DllCall("CloseHandle", Ptr, h)
   Return PID
}
 
GetInputLangName(langId)  {
   static LOCALE_SENGLANGUAGE := 0x1001
   charCount := DllCall("GetLocaleInfo", UInt, langId, UInt, LOCALE_SENGLANGUAGE, UInt, 0, UInt, 0)
   VarSetCapacity(localeSig, size := charCount << !!A_IsUnicode, 0)
   DllCall("GetLocaleInfo", UInt, langId, UInt, LOCALE_SENGLANGUAGE, Str, localeSig, UInt, size)
   return localeSig
}

VoiceRecord(mode := "start", filePath := "")  {
   commands := { start: ["open new type waveaudio alias recsound", "record recsound"]
               , stop:  ["save recsound " . filePath, "close recsound"] }
   for k, v in commands[mode]
      DllCall("Winmm\mciSendString", Str, v, Str, "", UInt, 0, Ptr, 0)
}

class chat {
	input(text, hide="") {
		global
		StringReplace, text, text, `%w, `{FFFFFF`}, All
		StringReplace, text, text, `%r, `{FF6347`}, All
		StringReplace, text, text, `%b, `{4169E1`}, All
		StringReplace, text, text, `\n, `n, All
		StringReplace, text, text, `\r, `r, All
		StringReplace, text, text, `\t, `t, All
		
		if !hide
			showDialog(DIALOG_STYLE_INPUT, "{4169E1}" title, "{FFFFFF}" text, "Закрыть", button2 := "", id := "0")
		else
			showDialog(DIALOG_STYLE_PASSWORD, "{4169E1}" title, "{FFFFFF}" text, "Закрыть", button2 := "", id := "0")
		
		dialogInputText =
		dialogCaptured = 0
		
		SetTimer, _commandprocessor, off
		settimer, checkEnter, 1
		while dialogCaptured = 0
			continue
		
		settimer, checkEnter, off
		SetTimer, _commandprocessor, 1
		gosub cancelDialog
		
		if (trim(dialogInputText) = "") {
			return -1
		}
		
		return Trim(dialogInputText)
	}
	
	show(text) {
		StringReplace, text, text, `%r, `{FF6347`}, All
		StringReplace, text, text, `%w, `{FFFFFF`}, All
		StringReplace, text, text, `%b, `{4169E1`}, All
		StringReplace, text, text, `%t, `{4169E1`}[GOS Helper]`{FFFFFF`}, All
		tmp_text := RegExReplace(text, "Ui)\{[a-f0-9]{6}\}")
		StringLen, len, tmp_text
		if len > 145
		{
			StringLeft, text, text, 145
			text = %text%...
		}
		return AddChatMessageEx(0xFFFFFFFF, text)
	}
	
	write(text) {
		if text = ERROR
			return
		
		ControlSend,, {F6}%text%{enter}, ahk_exe gta_sa.exe
	}
	
	send(text, forcibly=0) {
		if text = ERROR
			return
		
		if chat_queue
		{
			chat_queue := chat_queue text "`n"
			return
		}
		
		chat_queue := chat_queue text "`n"
		
		hotkey, f4, cancelchat
		hotkey, f4, on
		
		if forcibly
		{
			chat_forcibly = 1
			settimer, chat_queue, 1
		}
		else {
			chat_forcibly = 0
			settimer, chat_queue, 1100
		}
	}
	
	getQueueTime() {
		mstime := 0
		loop, parse, chat_queue, `n
			mstime+=1150
		
		return mstime
	}
}

cancelchat() {
	global
	hotkey, f4, off
	chat_queue := ""
	settimer, chat_queue, off
	chat.show("%t Очередь сообщений для отправки в чат очищена.")
	return
}

chat_queue() {
	if chat_forcibly
	{
		settimer, chat_queue, 1100
		chat_forcibly := 0
	}
	
	index = 0
	loop, parse, chat_queue, `n
	{
		index = 1
		queue_text := A_LoopField
		StringReplace, chat_queue, chat_queue, % A_LoopField "`n",,
		break
	}
	
	if (!cancelchat_msg) {
		cancelchat_msg = 1
		chat.show("%t Для отмены отправки сообщений в чат используйте клавишу %bF4%w.")
	}
	
	if index = 0
	{
		settimer, chat_queue, off
		hotkey, f4, cancelchat
		hotkey, f4, off
	}
	else
	{
		SendChat(queue_text)
		
		if (!chat_queue) ; чтобы не было "не флудите"
			sleep 1100
	}
}

class _vkmsg {
	id(args)
	{
		arg := vkmsg[args]
		Loop, parse, arg, `,
		{
			if A_Index = 1
				return A_LoopField
		}
	}
	
	firstName(args)
	{
		arg := vkmsg[args]
		Loop, parse, arg, `,
		{
			if A_Index = 2
				return A_LoopField
		}
	}
	
	lastName(args)
	{
		arg := vkmsg[args]
		Loop, parse, arg, `,
		{
			if A_Index = 3
				return A_LoopField
		}
	}
}

SetAppVolume(pid, volume)
{
    IMMDeviceEnumerator := ComObjCreate("{BCDE0395-E52F-467C-8E3D-C4579291692E}", "{A95664D2-9614-4F35-A746-DE8DB63617E6}")
    DllCall(NumGet(NumGet(IMMDeviceEnumerator+0)+4*A_PtrSize), "UPtr", IMMDeviceEnumerator, "UInt", 0, "UInt", 1, "UPtrP", IMMDevice, "UInt")
    ObjRelease(IMMDeviceEnumerator)

    VarSetCapacity(GUID, 16)
    DllCall("Ole32.dll\CLSIDFromString", "Str", "{77AA99A0-1BD6-484F-8BC7-2C654C9A9B6F}", "UPtr", &GUID)
    DllCall(NumGet(NumGet(IMMDevice+0)+3*A_PtrSize), "UPtr", IMMDevice, "UPtr", &GUID, "UInt", 23, "UPtr", 0, "UPtrP", IAudioSessionManager2, "UInt")
    ObjRelease(IMMDevice)

    DllCall(NumGet(NumGet(IAudioSessionManager2+0)+5*A_PtrSize), "UPtr", IAudioSessionManager2, "UPtrP", IAudioSessionEnumerator, "UInt")
    ObjRelease(IAudioSessionManager2)

    DllCall(NumGet(NumGet(IAudioSessionEnumerator+0)+3*A_PtrSize), "UPtr", IAudioSessionEnumerator, "UIntP", SessionCount, "UInt")
    Loop % SessionCount
    {
        DllCall(NumGet(NumGet(IAudioSessionEnumerator+0)+4*A_PtrSize), "UPtr", IAudioSessionEnumerator, "Int", A_Index-1, "UPtrP", IAudioSessionControl, "UInt")
        IAudioSessionControl2 := ComObjQuery(IAudioSessionControl, "{BFB7FF88-7239-4FC9-8FA2-07C950BE9C6D}")
        ObjRelease(IAudioSessionControl)

        DllCall(NumGet(NumGet(IAudioSessionControl2+0)+14*A_PtrSize), "UPtr", IAudioSessionControl2, "UIntP", ProcessId, "UInt")
        If (pid == ProcessId)
        {
            ISimpleAudioVolume := ComObjQuery(IAudioSessionControl2, "{87CE5498-68D6-44E5-9215-6DA47EF883D8}")
            DllCall(NumGet(NumGet(ISimpleAudioVolume+0)+3*A_PtrSize), "UPtr", ISimpleAudioVolume, "Float", MasterVolume/100.0, "UPtr", 0, "UInt")
            ObjRelease(ISimpleAudioVolume)
        }
        ObjRelease(IAudioSessionControl2)
    }
    ObjRelease(IAudioSessionEnumerator)
}

class str {
	checkCyrillic(text) {
		rus = 0
		characters = а,б,в,г,д,е,ё,ж,з,и,й,к,л,м,н,о,п,р,с,т,у,ф,х,ц,ч,ш,щ,ъ,ы,ь,э,ю,я,А,Б,В,Г,Д,Е,Ё,Ж,З,И,Й,К,Л,М,Н,О,П,Р,С,Т,У,Ф,Х,Ц,Ч,Ш,Щ,Ъ,Ы,Ь,Э,Ю,Я
		loop, parse, characters, `,
		{
			if text contains %A_LoopField%
			{
				rus = 1
				break
			}
		}
		return rus
	}

	checkLatin(text) {
		eng = 0
		characters = a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z
		loop, parse, characters, `,
		{
			if text contains %A_LoopField%
			{
				eng = 1
				break
			}
		}
		return eng
	}
	
	up(text) {
		StringUpper, rtn, text
		return rtn
	}
	
	down(text) {
		StringLower, rtn, text
		return rtn
	}
	
	upT(text) {
		StringUpper, rtn, text, T
		return rtn
	}
	
	downT(text) {
		StringLower, rtn, text, T
		return rtn
	}
	
	left(text, number) {
		StringLeft, rtn, text, % number
		return rtn
	}
	
	right(text, number) {
		StringRight, rtn, text, % number
		return rtn
	}
	
	len(text) {
		StringLen, rtn, text
		return rtn
	}
}

class gh {
	getState() {
		WinGet, WinList, List
		finded = 0
		count = 0
		npath = %A_ProgramFiles%\GOS Helper\gh.exe
	
		WinGet, winlist, list
		loop, %winlist%
		{
			wid := winlist%A_Index%
			WinGet, ProcessPath, ProcessPath, ahk_id %wid%
			
			if (processPath = npath)
				count++
		}
		
		if count > 2
			finded = 1
		
		return finded
	}
	
	getMyPID() {
		DetectHiddenWindows, On
		WinGet, mypid, PID, ahk_id %loadingwid%
		return mypid
	}
}

upload_imgur(path, imgurClient="d297fd441566f99") {
	File := FileOpen(path, "r")
	File.RawRead(Data, File.Length)
	Base64enc( PNGDATA, Data, File.Length )
	
	http := ComObjCreate("WinHttp.WinHttpRequest.5.1")
	http.Open("POST","https://api.imgur.com/3/image")
	http.SetRequestHeader("Authorization","Client-ID " imgurClient)
	
	http.Send(PNGDATA)
	codes := http.ResponseText
	if (json(codes, "success") = 0) {
		console.writeln("ERROR | imgur_upload response: " http.ResponseText)
		chat.show("%t%r Не удалось загрузить скриншот на имгур. Подробнее в отладке.")
		return 0
	}
	
	chat.show("%t Скриншот загружен на имгур.")
	return RegExReplace(json(codes, "data.link"),"\\")
}

uploadScreenToImgur() {
	if !arimgur
		return "<отключено>"
	
	sleep 3000
	RegExMatch(findchatline("Скриншот сохранен "), "i)Скриншот сохранен (.*)", outt)
	if outt1
	{
		Loop, parse, outt1, % A_Space
		{
			filename := A_LoopField
			break
		}
		
		chat.show("%t Попытка загрузки скриншота на имгур...")
		result := upload_imgur(path_screens "\" filename)
		return result
	}
	
	chat.show("%t%r Не удалось найти скриншот для загрузки на имгур.")
}

Base64enc( ByRef OutData, ByRef InData, InDataLen ) {
 DllCall( "Crypt32.dll\CryptBinaryToString" ( A_IsUnicode ? "W" : "A" )
        , UInt,&InData, UInt,InDataLen, UInt,1, UInt,0, UIntP,TChars, "CDECL Int" )
 VarSetCapacity( OutData, Req := TChars * ( A_IsUnicode ? 2 : 1 ) )
 DllCall( "Crypt32.dll\CryptBinaryToString" ( A_IsUnicode ? "W" : "A" )
        , UInt,&InData, UInt,InDataLen, UInt,1, Str,OutData, UIntP,Req, "CDECL Int" )
Return TChars
}

json(ByRef js, s, v = "") {
	j = %js%
	Loop, Parse, s, .
	{
		p = 2
		RegExMatch(A_LoopField, "([+\-]?)([^[]+)((?:\[\d+\])*)", q)
		Loop {
			If (!p := RegExMatch(j, "(?<!\\)(""|')([^\1]+?)(?<!\\)(?-1)\s*:\s*((\{(?:[^{}]++|(?-1))*\})|(\[(?:[^[\]]++|(?-1))*\])|"
				. "(?<!\\)(""|')[^\7]*?(?<!\\)(?-1)|[+\-]?\d+(?:\.\d*)?|true|false|null?)\s*(?:,|$|\})", x, p))
				Return
			Else If (x2 == q2 or q2 == "*") {
				j = %x3%
				z += p + StrLen(x2) - 2
				If (q3 != "" and InStr(j, "[") == 1) {
					StringTrimRight, q3, q3, 1
					Loop, Parse, q3, ], [
					{
						z += 1 + RegExMatch(SubStr(j, 2, -1), "^(?:\s*((\[(?:[^[\]]++|(?-1))*\])|(\{(?:[^{\}]++|(?-1))*\})|[^,]*?)\s*(?:,|$)){" . SubStr(A_LoopField, 1) + 1 . "}", x)
						j = %x1%
					}
				}
				Break
			}
			Else p += StrLen(x)
		}
	}
	If v !=
	{
		vs = "
		If (RegExMatch(v, "^\s*(?:""|')*\s*([+\-]?\d+(?:\.\d*)?|true|false|null?)\s*(?:""|')*\s*$", vx)
			and (vx1 + 0 or vx1 == 0 or vx1 == "true" or vx1 == "false" or vx1 == "null" or vx1 == "nul"))
			vs := "", v := vx1
		StringReplace, v, v, ", \", All
		js := SubStr(js, 1, z := RegExMatch(js, ":\s*", zx, z) + StrLen(zx) - 1) . vs . v . vs . SubStr(js, z + StrLen(x3) + 1)
	}
	Return, j == "false" ? 0 : j == "true" ? 1 : j == "null" or j == "nul"
		? "" : SubStr(j, 1, 1) == """" ? SubStr(j, 2, -1) : j
}

gosub checkstartreason

Gui, 1:Destroy
Gui, 1:+hwndmainwid +OwnDialogs -Caption +border
Gui, 1:Color, White
Gui, 1:Add, Progress, x-8 y-1 w490 h39 +c386aff hwndhcaption vStartControlHColor, 100

FileInstall, header_logo.png, %root%\header_logo.png
FileInstall, loading.gif, %root%\loading.gif, 1

random, randgreeting, 1, 2

RegRead, playername, HKEY_CURRENT_USER, SOFTWARE\SAMP, PlayerName
playername := Trim(playername)

Gui, 1:Add, Picture, x214 y-1 w38 h38 vStartControlHLogo +BackgroundTrans, %root%\header_logo.png
Gui, 1:Font, S15 CDefault, Segoe UI

Gui, 1:Add, Text, x22 y89 w430 h30 +Center vStartControlTitle, Добро пожаловать

Gui, 1:Font, S10 CDefault, Segoe UI
Gui, 1:Add, Text, x22 y123 w430 h60 +Center +cGray vStartControlText, Инициализация запуска...

try Gui, 1:Add, ActiveX, x200 y280 w70 h70 vStartControlGif, shell explorer
try StartControlGif.Navigate("about:blank")
try StartControlGif.document.write("<html>`n<title>name</title>`n<body>`n<center>`n<img src=""" root "\loading.gif"" >`n</center>`n</body>`n</html>")

Gui, 1:Font, S10 CDefault norm, Segoe UI
Gui, 1:Add, Text, x418 y3 w30 h20 +Center +cWhite +BackgroundTrans vHeaderButtonMinimize, __`n`nСвернуть

Gui, 1:Font, S13 CDefault, Segoe 
Gui, 1:Add, Text, x442 y5 w30 h30 +Center +BackgroundTrans +cWhite vHeaderButtonClose, x`n`nЗакрыть

Gui, 1:Show, w479 h379 NA, GOS Helper Beta
WinSet, Transparent, 0, ahk_id %mainwid%

IfWinNotActive, ahk_exe gta_sa.exe
	gosub ghactivate
else
	WinHide, ahk_id %mainwid%

SetTimer, uititle, 1
SetTimer, Watch_Hover,100

IfWinNotActive, ahk_exe gta_sa.exe
{
	if (start_argument1 = "minimize")
		WinHide, ahk_id %mainwid%
	else
		WinActivate, ahk_id %mainwid%
}

Menu, Tray, Tip, GOS Helper v%release%
Menu, Tray, Add, Активировать главное окно, ghactivate
Menu, Tray, Add, Перезапустить программу, reload
Menu, Tray, Add, Выход из программы, exitapp
Menu, Tray, MainWindow

GuiControl, 1:, StartControlText, Пожалуйста`, подождите...

Menu, Tray, Default, Активировать главное окно
Menu, Tray, Click, 1
Menu, Tray, NoStandard

global title := "GOS Helper Beta"
DllCall("kernel32.dll\SetProcessShutdownParameters", "UInt", 0x4FF, "UInt", 0)

console.writeln("INFO | Loading menu...")

Menu, game_menu, add, Режим 'F8 + Time', mode_f8time
Menu, game_menu, add, Показывать оверлей, showoverlay

Menu, vk_menu, add, Войти в аккаунт, vk_new_auth

Menu, roleplay_settings, add, Отыгровки для фракций, fractionrp
Menu, roleplay_settings, add, Индивидуальные отыгровки, individrp
Menu, roleplay_settings, add, Заполнить информацию о себе, aboutme
Menu, roleplay_settings, add, Настройка функции автореестра, settings_autoregister
Menu, roleplay_settings, add, Настройка автоматической отыгровки оружий, settings_autogunrp
Menu, roleplay_settings, add,
Menu, roleplay_settings, add, Автоматически надеть наручники после удара тайзером, autotazer
Menu, roleplay_settings, add, Автоматическая отыгровка оружий, autogunrp
Menu, roleplay_settings, add, Автоматически отыгрывать оружие`, если нажато на ПКМ, autogunrppkm
Menu, roleplay_settings, add, Автоматически пристегивать ремень, autorem
Menu, roleplay_settings, add, Автоматически отыграть`, что вы надели/сняли бронежилет, armourrp
Menu, roleplay_settings, Disable, Автоматически отыгрывать оружие`, если нажато на ПКМ

Menu, reportHelp, add, Помощник на посту, reportHelpPost
;Menu, reportHelp, add, Автоматическое собеседование, job_meeting
Menu, reportHelp, add, 
Menu, reportHelp, add, Сортировка скриншотов, sortscreenstate

Menu, help, add, Открыть папку программы, openfolder
Menu, help, add, Запустить установщик (удаление/переустановка/обновление), openinstaller
Menu, help, add, Ограничить использование сетевого трафика, netcontrol
Menu, help, add, Открыть страницу сообщества в ВКонтакте, vksite
Menu, help, add, Обратная связь, support
Menu, help, add, Горячие клавиши, hotkeys
Menu, help, add,
Menu, help, add, Запускать GH вместе с Windows, startupbutton

Menu, sup_menu, add, Подсчет ответов, supportresps
Menu, sup_menu, add, Показывать оверлей с вопросами, ov_allow_support

; Меню в окне
Menu, Gui, Add, Синхронизация папки с игрой, auto_copy
Menu, Gui, Add, Папка со скриншотами, open_screen
Menu, Gui, Add, 
Menu, Gui, Add, Игровое меню, :game_menu
Menu, Gui, Add, Функция ВКонтакте, :vk_menu
Menu, Gui, Add, Помощь в отчетах, :reportHelp
Menu, Gui, Add, Параметры для саппортов, :sup_menu
Menu, Gui, Add, Параметры отыгровок, :roleplay_settings
Menu, Gui, Add, Параметры программы/справка, :help

conServAtts = 0
connectServ:
setupInstallerCheck:
checkConfig()

_continue_start:
;GuiControl, 1:, StartControlText, Пожалуйста`, подождите...
;sleep 1000

GuiControl, show, StartControlGif
GuiControl, hide, StartControlTitle
GuiControl, hide, StartControlText

console.writeln("INFO | Creating a loading window...") ; textlow, textmain2

Gui, Font, S9 CGray, Segoe UI
Gui, Add, Text, x12 y349 w450 h30 +Center vprogressText, Загрузка...
Gui, Font, S15 CDefault, Segoe UI
Gui, Add, Text, x12 y49 w450 h30 +Center vWText, Что нового в этом обновлении...
Gui, Font, S9 CDefault, Segoe UI

updinfo = Это модернизированная версия, в которой нет зависимости от сервера GOS Helper. В этой версии нет чатов, онлайна и других функций, связанных с сервером GH.`n`nПрограмма не тестировалась в игре и может быть нестабильна, если кто-то хочет пофиксить баги, которые есть в этой версии - отправляйте Ваши pull-request'ы в GitHub.`n`nРазработано <a href="https://vk.com/strdev">Streleckiy Development</a> в далеком 06.01.2021 и модифицировано 17.03.2023.`nРепозиторий на GitHub: <a href="https://github.com/streleckiy/GOS-Helper-GTARP">https://github.com/streleckiy/GOS-Helper-GTARP</a>.

if indexlineupd > 11
	Gui, Add, Edit, x12 y84 w450 h210 vWUpdate +ReadOnly, % updinfo
else
	Gui, Add, Link, x12 y84 w450 h210 vWUpdate, % updinfo

console.writeln("INFO | Checking the registry...")
progressText("Получение информации о нике...")

while (true) {
	StringReplace, normalNick, playername, _, % " ", All
	if (playername == "")
	{
		InputBox, playername, % title, Укажите РП Ваш ник.
		if ((playername == ERROR) || (playername == "")) 
			goto GuiClose

		RegWrite, REG_SZ, HKEY_CURRENT_USER, SOFTWARE\SAMP, PlayerName, % playername
		continue
	}

	break
}

progressText("Получение информации о пути к игре...")
RegRead, gamepath, HKEY_CURRENT_USER, SOFTWARE\SAMP, LauncherDll

FileCreateDir, %path_screens%\GOS Helper

if token
{
	console.writeln("INFO | Checking the validity of the token...")
	vk_api("users.get&fields=screen_name", token)
	try first_name := api.response.0.first_name
	try last_name := api.response.0.last_name
	
	gosub _generateVK_Menu
	
	; generate vk_menu
	if vkmsg_rememberVirtIds
	{
		vkmsg_rememberVirtIds = 0
		gosub vkmsg_rememberVirtIds
	}
	
	if vkmsg_autoread
	{
		vkmsg_autoread = 0
		gosub vkmsg_autoread
	}

	if vkmsg_autoplayVoice
	{
		vkmsg_autoplayVoice = 0
		gosub vkmsg_autoplayVoice
	}
}

console.writeln("INFO | Loading settings from last session...")

if autotazer
{
	autotazer = 0
	gosub autotazer
}

ifexist, %A_Startup%\goshelper.lnk
{
	startupbutton = 1
	Menu, help, Check, Запускать GH вместе с Windows
}

if autogunrp
{
	autogunrp = 0
	gosub autogunrp
}

if showoverlay
{
	showoverlay = 0
	gosub showoverlay
}

if ov_allow_support
{
	ov_allow_support = 0
	gosub ov_allow_support
}

if mode_f8time
{
	mode_f8time = 0
	gosub mode_f8time
}

if supportresps
{
	supportresps = 0
	gosub supportresps
}

if sortscreenstate
{
	sortscreenstate = 0
	gosub sortscreenstate
}

if autogunrppkm
{
	autogunrppkm = 0
	gosub autogunrppkm
}

if autorem
{
	autorem = 0
	gosub autorem
}

if armourrp
{
	armourrp = 0
	gosub armourrp
}

if fraction
{
	gosub checkFractions
	if !fraction
		MsgBox, 16, % title, Укажите действительное название фракции.
}

if ((!rusnick) or (!rang) or (!fraction) or (!number)) {
	Gui, 1:+Disabled
	progressText("Ожидание действий пользователя...")
	
	gosub aboutme
	
	loop {
		IfWinNotExist, ahk_id %aboutmewid%
			break
	}
	
	if (!rusnick or !rang or !fraction or !number)
		exitapp
	
	Gui, 1:-Disabled
}

Loop, parse, rusnick, _
{
	if A_Index = 1
	{
		rus_name = %A_LoopField%
		continue
	}
	
	if A_Index = 2
	{
		rus_family = %A_LoopField%
		break
	}
}

if (!rus_name or !rus_family) or (str.CheckLatin(rusnick))
{
	progressText("Ожидание действий пользователя...")
	Gui, 1:+OwnDialogs
	MsgBox, 16, %title%, Указан не допустимый ник (напишите его по образцу)., 10
	IniWrite, % "", config.ini, Roleplay, rusnick
	reload
}

if autoregister ; тут не требуется назначение переменной
	gosub autoregister

ifnotexist, % A_ProgramFiles "\GOS Helper\overlay\dx9_overlay.dll"
{
	tooltip, Распаковываю архив чтобы работал оверлей.
	FileInstall, overlay_files.exe, %root%\overlay_files.exe
	RunWait, %root%\overlay_files.exe
	tooltip
}

Gui, 1:Default
hModule := DllCall("LoadLibrary", Str, A_ProgramFiles "\GOS Helper\overlay\dx9_overlay.dll")
if(hModule == -1 || hModule == 0)
{
	MsgBox, 48, % title, Dll файлы оверлея не могут быть загружены.
	Menu, game_menu, disable, Показывать оверлей
	Menu, game_menu, uncheck, Показывать оверлей
	Menu, sup_menu, disable, Показывать оверлей с вопросами
	Menu, game_menu, uncheck, Показывать оверлей
}

progressText("Загрузка библиотеки: overlay...")
Init_func 				:= DllCall("GetProcAddress", UInt, hModule, Str, "Init")
SetParam_func 			:= DllCall("GetProcAddress", UInt, hModule, Str, "SetParam")

TextCreate_func 		:= DllCall("GetProcAddress", UInt, hModule, Str, "TextCreate")
TextDestroy_func 		:= DllCall("GetProcAddress", UInt, hModule, Str, "TextDestroy")
TextSetShadow_func 		:= DllCall("GetProcAddress", UInt, hModule, Str, "TextSetShadow")
TextSetShown_func 		:= DllCall("GetProcAddress", UInt, hModule, Str, "TextSetShown")
TextSetColor_func 		:= DllCall("GetProcAddress", UInt, hModule, Str, "TextSetColor")
TextSetPos_func 		:= DllCall("GetProcAddress", UInt, hModule, Str, "TextSetPos")
TextSetString_func 		:= DllCall("GetProcAddress", UInt, hModule, Str, "TextSetString")
TextUpdate_func 		:= DllCall("GetProcAddress", UInt, hModule, Str, "TextUpdate")

BoxCreate_func 			:= DllCall("GetProcAddress", UInt, hModule, Str, "BoxCreate")
BoxDestroy_func 		:= DllCall("GetProcAddress", UInt, hModule, Str, "BoxDestroy")
BoxSetShown_func 		:= DllCall("GetProcAddress", UInt, hModule, Str, "BoxSetShown")
BoxSetBorder_func		:= DllCall("GetProcAddress", UInt, hModule, Str, "BoxSetBorder")
BoxSetBorderColor_func 	:= DllCall("GetProcAddress", UInt, hModule, Str, "BoxSetBorderColor")
BoxSetColor_func		:= DllCall("GetProcAddress", UInt, hModule, Str, "BoxSetColor")
BoxSetHeight_func		:= DllCall("GetProcAddress", UInt, hModule, Str, "BoxSetHeight")
BoxSetPos_func			:= DllCall("GetProcAddress", UInt, hModule, Str, "BoxSetPos")
BoxSetWidth_func		:= DllCall("GetProcAddress", UInt, hModule, Str, "BoxSetWidth")

LineCreate_func 		:= DllCall("GetProcAddress", UInt, hModule, Str, "LineCreate")
LineDestroy_func		:= DllCall("GetProcAddress", UInt, hModule, Str, "LineDestroy")
LineSetShown_func		:= DllCall("GetProcAddress", UInt, hModule, Str, "LineSetShown")
LineSetColor_func 		:= DllCall("GetProcAddress", UInt, hModule, Str, "LineSetColor")
LineSetWidth_func		:= DllCall("GetProcAddress", UInt, hModule, Str, "LineSetWidth")
LineSetPos_func			:= DllCall("GetProcAddress", UInt, hModule, Str, "LineSetPos")

ImageCreate_func 		:= DllCall("GetProcAddress", UInt, hModule, Str, "ImageCreate")
ImageDestroy_func		:= DllCall("GetProcAddress", UInt, hModule, Str, "ImageDestroy")
ImageSetShown_func		:= DllCall("GetProcAddress", UInt, hModule, Str, "ImageSetShown")
ImageSetAlign_func 		:= DllCall("GetProcAddress", UInt, hModule, Str, "ImageSetAlign")
ImageSetPos_func		:= DllCall("GetProcAddress", UInt, hModule, Str, "ImageSetPos")
ImageSetRotation_func	:= DllCall("GetProcAddress", UInt, hModule, Str, "ImageSetRotation")

DestroyAllVisual_func	:= DllCall("GetProcAddress", UInt, hModule, Str, "DestroyAllVisual")
ShowAllVisual_func		:= DllCall("GetProcAddress", UInt, hModule, Str, "ShowAllVisual")
HideAllVisual_func 		:= DllCall("GetProcAddress", UInt, hModule, Str, "HideAllVisual")

GetFrameRate_func 		:= DllCall("GetProcAddress", UInt, hModule, Str, "GetFrameRate")
GetScreenSpecs_func 	:= DllCall("GetProcAddress", UInt, hModule, Str, "GetScreenSpecs")

SetCalculationRatio_func:= DllCall("GetProcAddress", UInt, hModule, Str, "SetCalculationRatio")
SetOverlayPriority_func := DllCall("GetProcAddress", UInt, hModule, Str, "SetOverlayPriority")

IniRead, lastStatusWork, %A_ProgramFiles%\GOS Helper\config.ini, work, status
if lastStatusWork = 1
{
	progressText("Не понял юмора, дай-ка перезапущусь...")
	reload
}

;flash_text = 0
;settimer, flash_text, 500
;sleep 1500

_updatecontinue:
FileDelete, % path_chatlog
progressText("Создание таймеров...")

SetTimer, gh_main_hk, 100
SetTimer, chatlogger, 300
SetTimer, healthsys, 2000
SetTimer, checkGameLoop, 1500
SetTimer, not_responding_test, 5000
SetTimer, _commandprocessor, 1
settimer, devloop, 100

ghtruck.dropAll()

GuiControl, enable, start_game
GuiControl, enable, showmenu

oldplayerhealth := getPlayerHealth()
oldplayerarmour := getPlayerArmour()

IfWinExist, ahk_exe gta_sa.exe
{
	IfWinActive, ahk_exe gta_sa.exe
		printlow("GOS Helper was connected.", 1500)
	
	game_loaded = 1
	is_authed = 1
	console.writeln("INFO | GOS Helper was connected to game.")
}

;Gui, Menu, Gui
GuiControl, hide, StartControlGif
IniWrite, 0, %A_ProgramFiles%\GOS Helper\config.ini, work, status
Button.Push(New Button_Type1(x:=139,y:=305,w:=100,h:=35,text:="В игру (G)",FontSize:=10,name:="Start_Game",label:="Start_Game",Window:=1,Color:=""))
Button.Push(New Button_Type1(x:=239,y:=305,w:=100,h:=35,text:="Меню GH (M)",FontSize:=10,name:="ShowMenu",label:="ShowMenu",Window:=1,Color:=""))

chat.show("%t Готов к работе. Введите в игре /gh.")
progressText("Готово.")

console.writeln("INFO | GOS Helper loaded.")
gh_loaded = 1

GuiControl, hide, progresstext
Gui, Add, Text, x12 y349 w450 h30 +Center +c4169E1 gSupport vSupportButton, Связь c технической поддержкой GH

IfWinExist, ahk_exe gta_sa.exe
{
	if !owc
	{
		overlay.create()
		if ((is_sub) & (afktime)) {
			afktime = 0
			Menu, subfuncs, Check, Подсчет времени в AFK
			gosub afktime
			overlay.createAFK()
		}
		
		if (ov_allow_support) {
			overlay.createSupport()
		}
		
		if ((afk_overlay_id = -1) || (overlay_id = -1) || (sup_overlay_id = -1)) {
			chat.show(msg_overlay_error1)
			chat.show(msg_overlay_error2)
		}
		
		owc = 1
	}
}
return

ExitApp:
ExitApp

autogunrp:
if !autogunrp
{
	Menu, roleplay_settings, Check, Автоматическая отыгровка оружий
	weapon := getPlayerWeaponId()
	oweapon := getPlayerWeaponId()
	IniWrite, 1, config.ini, Roleplay, autogunrp
	autogunrp = 1
	settimer, gunloop, 500
	Menu, roleplay_settings, Enable, Автоматически отыгрывать оружие`, если нажато на ПКМ
	return
}
else {
	Menu, roleplay_settings, UnCheck, Автоматическая отыгровка оружий
	IniWrite, 0, config.ini, Roleplay, autogunrp
	autogunrp = 0
	settimer, gunloop, off
	Menu, roleplay_settings, Disable, Автоматически отыгрывать оружие`, если нажато на ПКМ
}
return

vkmsg_autoread:
if !vkmsg_autoread
{
	Menu, vk_menu, Check, Автоматически прочитывать полученное сообщение
	IniWrite, 1, config.ini, vkfuncs, autoread
	vkmsg_autoread = 1
	return
}
else {
	Menu, vk_menu, UnCheck, Автоматически прочитывать полученное сообщение
	IniWrite, 0, config.ini, vkfuncs, autoread
	vkmsg_autoread = 0
}
return

vkmsg_rememberVirtIds:
if !vkmsg_rememberVirtIds
{
	Menu, vk_menu, Check, Сохранять виртуальные идентификаторы
	Menu, vk_menu, Enable, Записанные виртуальные идентификаторы
	IniWrite, 1, config.ini, vkfuncs, rememberVirtIds
	vkmsg_rememberVirtIds = 1
	
	ifnotexist, virt_ids.ini
	{
		fileappend, % "# Последняя строка должна быть пуста.`n", virt_ids.ini
		fileappend, % "# Допустимый формат записи: ЦИФРОВОЙ ID,ИМЯ,ФАМИЛИЯ`n`n", virt_ids.ini
	}
	
	loop, read, virt_ids.ini
	{
		if (str.left(A_LoopReadLine, 1) = "#")
			continue
		
		if (A_LoopReadLine != "")
			vkmsg[vkmsg.MaxIndex()+1] := A_LoopReadLine
	}
	return
}
else {
	gui, +owndialogs
	MsgBox, 49, % title, Записанная база виртуальных идентификаторов VKMSG будет удалена.
	IfMsgBox, ok
	{
		filedelete, virt_ids.ini
		Menu, vk_menu, UnCheck, Сохранять виртуальные идентификаторы
		IniWrite, 0, config.ini, vkfuncs, rememberVirtIds
		vkmsg_rememberVirtIds = 0
	}
	Menu, vk_menu, Disable, Записанные виртуальные идентификаторы
}
return

vkmsg_autoplayVoice:
if !vkmsg_autoplayVoice
{
	Menu, vk_menu, Check, Автоматически прослушивать голосовые сообщения
	IniWrite, 1, config.ini, vkfuncs, autoplayVoice
	vkmsg_autoplayVoice = 1
	return
}
else {
	Menu, vk_menu, UnCheck, Автоматически прослушивать голосовые сообщения
	IniWrite, 0, config.ini, vkfuncs, autoplayVoice
	vkmsg_autoplayVoice = 0
}
return

mode_f8time:
if !mode_f8time
{
	Menu, game_menu, Check, Режим 'F8 + Time'
	IniWrite, 1, config.ini, game, mode_f8time
	mode_f8time = 1
	hotkey, F8, mode_f8hk
	hotkey, F8, on
	return
}
else {
	Menu, game_menu, UnCheck, Режим 'F8 + Time'
	IniWrite, 0, config.ini, game, mode_f8time
	mode_f8time = 0
	hotkey, F8, off
}
return

autogunrppkm:
if !autogunrppkm
{
	Menu, roleplay_settings, Check, Автоматически отыгрывать оружие`, если нажато на ПКМ
	IniWrite, 1, config.ini, Roleplay, autogunrppkm
	autogunrppkm = 1
	return
}
else {
	Menu, roleplay_settings, UnCheck, Автоматически отыгрывать оружие`, если нажато на ПКМ
	IniWrite, 0, config.ini, Roleplay, autogunrppkm
	autogunrppkm = 0
}
return

autorem:
if !autorem
{
	Menu, roleplay_settings, Check, Автоматически пристегивать ремень
	settimer, _autorem, 500
	IniWrite, 1, config.ini, Roleplay, autorem
	autorem = 1
}
else {
	Menu, roleplay_settings, UnCheck, Автоматически пристегивать ремень
	settimer, _autorem, off
	IniWrite, 0, config.ini, Roleplay, autorem
	autorem = 0
}
return

armourrp:
if !armourrp
{
	Menu, roleplay_settings, Check, Автоматически отыграть`, что вы надели/сняли бронежилет
	armourrp = 1
	IniWrite, 1, config.ini, Roleplay, armourrp
}
else {
	Menu, roleplay_settings, UnCheck, Автоматически отыграть`, что вы надели/сняли бронежилет
	armourrp = 0
	IniWrite, 0, config.ini, Roleplay, armourrp
}
return

settings_autogunrp:
Gui, autogunrp:Destroy
Gui, autogunrp:-MinimizeBox +hwndautogunrpwid +Resize
Gui, autogunrp:Color, White
Gui, autogunrp:Font, S11 CDefault Bold, Segoe UI
Gui, autogunrp:Add, text, section, Автоматическая отыгровка оружий
Gui, autogunrp:Font, S9 CDefault norm, Segoe UI
Gui, autogunrp:Add, Link,, Иногда нужно нажимать ПКМ дважды`, для того чтобы открыть меню взаимодействия с отыгровкой.`nНажмите <a href="gunrp.ini">сюда</a> для ручной настройки.
Gui, autogunrp:Font, S8 CDefault norm, Segoe UI
LV_Delete()
Gui, autogunrp:Add, ListView, w400 h200 vAutoGunList +NoSortHdr -Multi, ID Оружия|Достал оружие|Убрал оружие
Gui, autogunrp:Show, w778 h400, % title ; w: 778 | h: 400
Gui, autogunrp:Default

gun_section := ""

reload_autogunrp:
Loop, read, gunrp.ini, `n
{
	if (A_LoopReadLine = "[on]")
		gun_section = on
	
	if (A_LoopReadLine = "[off]")	
		break
	
	if !gun_section
		continue
	
	RegExMatch(A_LoopReadLine, "id(.*)=(.*)", out)
	if (out1 or out2)
	{
		loop, parse, out2, `|
		{
			if A_Index = 1
				out2 := A_LoopField
		}
		
		if gun_section = on
		{
			IniRead, gunrp_temp, gunrp.ini, off, id%out1%
			if gunrp_temp = Error
			{
				Gui, autogunrp:+OwnDialogs
				
				if out1 = 0
					MsgBox, 16, % title, Найдена отыгровка при "доставании" оружия`, но не найдена отыгровка при его "прятании". Исправьте это. ID оружия: %out1%., 30
			}
			
			loop, parse, gunrp_temp, `|
			{
				if A_Index = 1
					gunrp_temp := A_LoopField
			}
			
			LV_Add("", out1, out2, gunrp_temp)
		}
	}
}

LV_ModifyCol()
settimer, loop_settings_autogunrp, 1
loop_settings_autogunrp:
IfWinNotExist, ahk_id %autogunrpwid%
{
	settimer, loop_settings_autogunrp, off
	return
}
	
IfWinNotActive, ahk_id %autogunrpwid%
	return

Gui, autogunrp:Default

if GetKeyState("Escape", "P")
	Gui, autogunrp:Destroy

if (GetKeyState("AppsKey", "P") or GetKeyState("RButton", "P"))
{
	Menu, AutoGunRP, add, nul, nul
	FocusedRowNumber := LV_GetNext(0, "F")
	if (!FocusedRowNumber)
	{
		Menu, AutoGunRP, DeleteAll
		Menu, AutoGunRP, Add, Создать отыгровку, nul
		Menu, AutoGunRP, Show
		
		if A_ThisMenuItem = Создать отыгровку
			goto AutoGunRP_CreateRP
		
		return
	}
	
	LV_GetText(focusedAutoGUNRPID, FocusedRowNumber, 1)
	LV_GetText(focusedAutoGUNRPON, FocusedRowNumber, 2)
	LV_GetText(focusedAutoGUNRPOFF, FocusedRowNumber, 3)
	
	Menu, AutoGunRP, DeleteAll
	Menu, AutoGunRP, Add, Создать отыгровку, nul
	Menu, AutoGunRP, Add, Изменить отыгровку, nul
	Menu, AutoGunRP, Add, Удалить отыгровку, nul
	Menu, AutoGunRP, Show
	
	if A_ThisMenuItem = Создать отыгровку
		goto autogunrp_createrp
	
	if A_ThisMenuItem = Изменить отыгровку
		goto autogunrp_editrp
	
	if A_ThisMenuItem = Удалить отыгровку
		goto autogunrp_removerp
	
	return
}
return

SaveAutoregister:
gui, autoregister:submit, nohide
fileappend, % autoregister_rp_text, % autoregister_path

settings_autoregister:
if (!isFullFraction()) {
	MsgBox, 16, % title, Недоступно для Вашей организации.
	return
}

Gui, autoregister:Destroy
Gui, autoregister:-MinimizeBox +hwndautoregisterwid
Gui, autoregister:Color, White
Gui, autoregister:Font, S11 CDefault Bold, Segoe UI
Gui, autoregister:Add, text, section, Настройки автоматического реестра
Gui, autoregister:Font, S9 CDefault norm, Segoe UI

if Autoregister
	Gui, autoregister:Add, Checkbox, +Checked gAutoregister vAutoregister, Включить функцию
else
	Gui, autoregister:Add, Checkbox, -Checked gAutoregister vAutoregister, Включить функцию

if arimgur
	Gui, autoregister:Add, Checkbox, +Checked gARImgur vARImgur, Автоматически загружать на имгур
else
	Gui, autoregister:Add, Checkbox, -Checked gARImgur vARImgur, Автоматически загружать на имгур

if arsavescreens
	Gui, autoregister:Add, Checkbox, +Checked garsavescreens varsavescreens, Делать скриншот во время занесения (если не требуется, можете отключить)
else
	Gui, autoregister:Add, Checkbox, -Checked garsavescreens varsavescreens, Делать скриншот во время занесения (если не требуется, можете отключить)

Gui, autoregister:Add, Button, gAutoregisterButtonEdit section, Изменить отыгровку
Gui, autoregister:Add, Button, gAutoregister_Format ys, Изменить формат
Gui, autoregister:Add, Button, gAutoregister_EditRank ys, Изменить ранги
Gui, autoregister:Add, Button, gAutoregister_Open ys, Занесенные игроки
Gui, autoregister:Add, Button, gAutoregister_Insert ys, Вставить в таблицу
Gui, autoregister:Add, Button, gAutoregisterButtonActivate ys, Как активировать?
Gui, autoregister:Show,, % title

settimer, _autoregisterloop, 1

_autoregisterloop:
IfWinNotExist, ahk_id %autoregisterwid%
{
	settimer, _autoregisterloop, off
	return
}

IfWinNotActive, ahk_id %autoregisterwid%
	return

if GetKeyState("Escape", "P")
	gui, autoregister:destroy

return

autoregister_open:
gui, autoregister:+owndialogs
ifnotexist, autoregister\register.txt
{
	MsgBox, 64, % title, Вы еще никого не записали.
	return
}

Run, autoregister\register.txt,, UseErrorLevel
if errorlevel
	MsgBox, 16, % title, Ошибка открытия файла: autoregister\register.txt.

return

AutoregisterButtonActivate:
Gui, autoregister:+owndialogs
MsgBox, 64, % title, 
(
/arinvite - принять человека в организацию.
/aruninvite - выгнать человека из организации.
/arrank - выдать человеку ранг.

Для ФСБ:
/arfuninvite - уволить человека из другой организации.
/arfrank - выдать ранг человеку из другой организации.
)
return

AutogunrpGuiSize:
GuiControl, move, AutoGunList, % "w" A_GuiWidth-28 " h" A_GuiHeight-95
return

autogunrp_removerp:
MsgBox, 52, % title, Вы действительно желаете удалить отыгровку под ид. %focusedAutoGunRPID%?
IfMsgBox, no
	return

IniDelete, gunrp.ini, on, id%focusedAutoGunRPID%
IniDelete, gunrp.ini, off, id%focusedAutoGunRPID%
goto settings_autogunrp
return

autogunrp_editRP:
from_edit = 1
Gui, autogunrp_edit:Destroy
Gui, autogunrp_edit:+AlwaysOnTop +hwndautogunrp_editwid
Gui, autogunrp_edit:Color, White
Gui, autogunrp_edit:Font, CDefault S11 Bold, Segoe UI
Gui, autogunrp_edit:Add, Text,, Изменение отыгровки оружия
Gui, autogunrp_edit:Font, CDefault S9 Norm, Segoe UI
Gui, autogunrp_edit:Add, Text,, Используйте знак "|" для разделения строки на еще одну.`nРекомендуется использовать 2 строки отыгровки.
Gui, autogunrp_edit:Add, Text,, Укажите ID оружия, для которого будет отыгровка
Gui, autogunrp_edit:Add, Edit, vNewAutoGunRP_ID number w400 disabled, % focusedAutoGUNRPID
Gui, autogunrp_edit:Add, Text,, Укажите отыгровку`, которая будет отыгроваться`, когда вы достаете оружие
Gui, autogunrp_edit:Add, Edit, vNewAutoGunRP_ON w400, % focusedAutoGUNRPON
Gui, autogunrp_edit:Add, Text,, Укажите отыгровку`, которая будет отыгрываться`, когда вы убираете оружие
Gui, autogunrp_edit:Add, Edit, vNewAutoGunRP_OFF w400, % focusedAutoGUNRPOFF
Gui, autogunrp_edit:Add, Button, gSaveAutoGunRP_createRP, Применить
Gui, autogunrp_edit:Show,, % title
settimer, _autogunrploop, 1

gosub loop_settings_autogunrp

_autogunrploop:
IfWinNotExist, ahk_id %autogunrp_editwid%
{
	settimer, _autogunrploop, off
	return
}

IfWinNotActive, ahk_id %autogunrp_editwid%
	return

if GetKeyState("Escape", "P")
{
	KeyWait, Escape, U
	Gui, autogunrp_edit:Destroy
}
return

autogunrp_createRP:
from_edit = 0
Gui, autogunrp_edit:Destroy
Gui, autogunrp_edit:+AlwaysOnTop +hwndautogunrp_editwid
Gui, autogunrp_edit:Color, White
Gui, autogunrp_edit:Font, CDefault S11 Bold, Segoe UI
Gui, autogunrp_edit:Add, Text,, Создание новой отыгровки оружия
Gui, autogunrp_edit:Font, CDefault S9 Norm, Segoe UI
Gui, autogunrp_edit:Add, Text,, Используйте знак "|" для разделения строки на еще одну.`nРекомендуется использовать 2 строки отыгровки.
Gui, autogunrp_edit:Add, Text,, Укажите ID оружия, для которого будет отыгровка
Gui, autogunrp_edit:Add, Edit, vNewAutoGunRP_ID number w400 , 
Gui, autogunrp_edit:Add, Text,, Укажите отыгровку`, которая будет отыгроваться`, когда вы достаете оружие
Gui, autogunrp_edit:Add, Edit, vNewAutoGunRP_ON w400, 
Gui, autogunrp_edit:Add, Text,, Укажите отыгровку`, которая будет отыгрываться`, когда вы убираете оружие
Gui, autogunrp_edit:Add, Edit, vNewAutoGunRP_OFF w400, 
Gui, autogunrp_edit:Add, Button, gSaveAutoGunRP_createRP, Применить
Gui, autogunrp_edit:Show,, % title
settimer, _autogunrp1loop, 1

_autogunrp1loop:
IfWinNotExist, ahk_id %hwndautogunrp_editwid%
{
	SetTimer, _autogunrp1loop, off
	return
}

IfWinNotActive, ahk_id %autogunrp_editwid%
	return

if GetKeyState("Escape", "P")
{
	KeyWait, Escape, U
	Gui, autogunrp_edit:Destroy
}
return

SaveAutoGunRP_CreateRP:
newautogunrp_id := ""
newautogunrp_on := ""
newautogunrp_off := ""

Gui, autogunrp_edit:Submit, NoHide

if NewAutoGunRP_ID =
{
	Gui, autogunrp_edit:+OwnDialogs
	MsgBox, 16, % title, Вы не ввели ID оружия.
	return
}

if NewAutoGunRP_ON =
{
	Gui, autogunrp_edit:+OwnDialogs
	MsgBox, 16, % title, Вы не ввели отыгровку при "доставании" оружия.
	return
}

if NewAutoGunRP_OFF =
{
	Gui, autogunrp_edit:+OwnDialogs
	MsgBox, 16, % title, Вы не ввели отыгровку при "убирании" оружия.
	return
}

if NewAutoGunRP_ID = 0
{
	Gui, autogunrp_edit:+OwnDialogs
	MsgBox, 16, % title, Вы не можете использовать ID 0`, так как он отвечает за кулаки.
	return
}

NewAutoGunRP_ID := Round(NewAutoGunRP_ID)

IniWrite, %NewAutoGunRP_ON%, gunrp.ini, on, id%NewAutoGunRP_ID%
IniWrite, %NewAutoGunRP_OFF%, gunrp.ini, off, id%NewAutoGunRP_ID%

Gui, autogunrp_edit:destroy
goto settings_autogunrp
return

nul: ; нулевой пункт меню
return

GunLoop:
IfWinNotActive, ahk_exe gta_sa.exe
	return

if wait_alternative = 1
	return

if !game_loaded
	return

if !from_alternative_gun
{
	weapon := getPlayerWeaponId()
	if (weapon = oweapon)
		return
}

if autogunrppkm
{
	if !GetKeyState("RButton", "P")
		return
}

oweapon := weapon
from_alternative_gun = 0

IniRead, weapon_autogunrp_text_on, gunrp.ini, on, id%weapon%
IniRead, weapon_autogunrp_text_off, gunrp.ini, off, id%from_weapon%

if (weapon_autogunrp_text_on = "ERROR") {
	loop, parse, weapon_autogunrp_text_off, `|
		chat.send(A_LoopField, 1)
	
	from_weapon := weapon
	return
}

if (weapon_autogunrp_text_off = "ERROR") {
	loop, parse, weapon_autogunrp_text_on, `|
		chat.send(A_LoopField, 1)
	
	from_weapon := weapon
	return
}

if (weapon != from_weapon)
{
	loop, parse, weapon_autogunrp_text_off, `|
		chat.send(A_LoopField, 1)
	
	from_weapon := weapon
}

if weapon != 0
{
	loop, parse, weapon_autogunrp_text_on, `|
		chat.send(A_LoopField, 1)
}

from_weapon := weapon
return

Start_Game:
IfWinNotExist, ahk_exe gta_sa.exe
{
	tooltip, Загружаем информацию...
	gtarp_api("query=get_server_list")
	
	try
	{
		online_server01 := gtarp_api.response.0.players
		title_server01 := gtarp_api.response.0.title
		
		online_server02 := gtarp_api.response.1.players
		title_server02 := gtarp_api.response.1.title
	}
	
	if ((Trim(online_server01) = "") & (Trim(slots_server01) = "") & (Trim(title_server01) = "") & (Trim(online_server02) = "") & (Trim(slots_server02) = "") (Trim(title_server02) = "") & (Trim(online_server01) = "") & (Trim(slots_server01) = "") (Trim(title_server01) = "")) {
		online_server01 := "н/д"
		title_server01 := "01 сервер"
		
		online_server02 := "н/д"
		title_server02 := "02 сервер"
	}
	
	ToolTip
	Gui, 1:default
	GuiControl, hide, Start_Game
	GuiControl, hide, SupportButton
	GuiControl, hide, ShowMenu
	GuiControl, hide, WText
	GuiControl, hide, WUpdate
	GuiControl, hide, progresstext
	
	Gui, Start_Game:Destroy
	Gui, Start_Game:-Caption +hwndstartgamemenu
	Gui, Start_Game:Color, White
	Gui, Start_Game:Font, S14 CDefault bold, Segoe UI
	Gui, Start_Game:Add, Text, x12 y55 w450 h30 +Center, Выберите сервер
	Gui, Start_Game:Font, S30 CDefault , Segoe UI
	Gui, Start_Game:Add, Text, x32 y100 w90 h50 +Center, % online_server01
	Gui, Start_Game:Add, Text, x352 y100 w90 h50 +Center, % online_server02
	Gui, Start_Game:Font, S9 CDefault norm, Segoe UI
	;Gui, Start_Game:Add, GroupBox, x12 y39 w450 h10 , 
	Gui, Start_Game:Add, Text, x32 y161 w90 h20 +Center, % title_server01
	Gui, Start_Game:Add, Text, x352 y161 w90 h20 +Center, % title_server02
	Gui, Start_Game:Font, S10 CDefault, Segoe UI
	
	Button.Push(New Button_Type1(x:=22,y:=230,w:=110,h:=30,text:="Играть",FontSize:=10,name:="Start01Server",label:="Start01server",Window:="Start_Game",Color:=""))
	Button.Push(New Button_Type1(x:=347,y:=230,w:=110,h:=30,text:="Играть",FontSize:=10,name:="Start02Server",label:="Start02server",Window:="Start_Game",Color:=""))
	
	Gui, Start_Game:Font, S9 CDefault, Segoe UI
	;Gui, Start_Game:Add, Text, x142 y125 w190 +Center, Если Вы устанавливали скрипты из коллекции GH или изменяли сборку`, то галочку ниже нужно убрать.
	Gui, Start_Game:Add, Text, x12 y320 w450 h30 +Center +cGray gStart_GameGuiClose, Нажмите Escape чтобы выйти из этого меню.
	Gui, Start_Game:+Parent1
	Gui, Start_Game:Show, x1 y30, % title
	
	settimer, start_gameBG, 1
	SetTimer, uititle, off
	SetTimer, Watch_Hover,off
}
else {
	Gui, 1:+OwnDialogs
	settimer, timer_game_close, 1
	MsgBox, 68, % title, Игра уже запущена. Желаете ее закрыть?
	IfMsgBox, yes
		process, close, gta_sa.exe
}
return

timer_game_close:
settimer, timer_game_close, off
TGC_ID := ""
WinGet, TGC_ID, ID, % title, Игра уже запущена. Желаете ее закрыть?
Control, Disable,, Button1, ahk_id %TGC_ID%
ControlSetText, Button1, Да (3), ahk_id %TGC_ID%
sleep 1000
ControlSetText, Button1, Да (2), ahk_id %TGC_ID%
sleep 1000
ControlSetText, Button1, Да (1), ahk_id %TGC_ID%
sleep 1000
ControlSetText, Button1, Да, ahk_id %TGC_ID%
Control, Enable,, Button1, ahk_id %TGC_ID%
return

Start_GameGuiClose:
SetTimer, Watch_Hover, 100
Gui, Start_Game:destroy

settimer, start_gameBG, off
SetTimer, uititle, on
SetTimer, Watch_Hover, on

Gui, 1:default
GuiControl, show, Start_Game
GuiControl, show, SupportButton
GuiControl, show, ShowMenu
GuiControl, show, WText
GuiControl, show, WUpdate
GuiControl, show, progresstext
return

start_gameBG:
IfWinActive, ahk_id %startgamemenu%
	WinActivate, ahk_id %mainwid%

IfWinNotExist, ahk_id %startgamemenu%
{
	SetTimer, Watch_Hover, 100
	settimer, start_gameBG, off
	return
}

IfWinNotActive, ahk_id %mainwid%
	return

if GetKeyState("Escape", "P")
	gosub Start_GameGuiClose

if GetKeyState("1", "P") {
	goto start01server
}

if GetKeyState("2", "P") {
	goto start02server
}
return

Start01Server:
gosub Start_GameGuiClose
filedelete, % path_chatlog

game_loaded = 0
is_authed = 0
server = 01
owc = 0

Gui, Start_Game:Destroy
gosub syncwithgame
started_from_ghlauncher = 1

progresstext("Инициализация старта игры...")
gosub checkGameLoop
sleep 1000

progressText("Игра запускается...")
console.writeln("INFO | Starting the game...")
Run, %gamepath%\samp.exe 01.gtarp.ru:7777,, UseErrorLevel, gamepid
ToolTip
if errorlevel
{
	Gui, 1:+OwnDialogs
	MsgBox, 16, % title, Не удалось запустить %gamepath%\samp.exe.
	return
}

console.writeln("INFO | Waiting for the game window...")
WinWait, ahk_exe gta_sa.exe
progressText("Игра запущена.")
console.writeln("INFO | Game started.")
settimer, escapeCheck, 1
ghapi_online = 1

loop {
	process, exist, % gamepid
	if (errorlevel = 0)
		break
	
	if game_loaded
		break
}

console.writeln("INFO | Game breaked/loaded.")

if (gameWaitLogin()) {
	console.writeln("INFO | User authed in server.")
	is_authed = 1

	if (trim(clist) != "") {
		if clist is integer
		{
			chat.send("/clist " clist)
			chat.show("%t Установлен " clist "-й клист.")
		}
	}
}
return

Start02Server:
gosub Start_GameGuiClose
filedelete, % path_chatlog

game_loaded = 0
is_authed = 0
server = 02
owc = 0

Gui, Start_Game:Destroy
Gui, 1:Default

gosub syncwithgame
progresstext("Инициализация старта игры...")
started_from_ghlauncher = 1
gosub checkGameLoop
sleep 1000

progressText("Игра запускается...")
console.writeln("INFO | Starting the game...")
Run, %gamepath%\samp.exe 02.gtarp.ru:7777,, UseErrorLevel, gamepid
if errorlevel
{
	Gui, 1:+OwnDialogs
	MsgBox, 16, % title, Не удалось запустить %gamepath%\samp.exe.
	return
}

console.writeln("INFO | Waiting for the game window...")
WinWait, ahk_exe gta_sa.exe
progressText("Игра запущена.")
console.writeln("INFO | Game started.")
settimer, escapeCheck, 1

loop {
	process, exist, % gamepid
	if (errorlevel = 0)
		break
	
	if game_loaded
		break
}

console.writeln("INFO | Game breaked/loaded.")
if (gameWaitLogin()) {
	console.writeln("INFO | User authed in server.")
	if (clist) {
		is_authed = 1
		chat.send("/clist " clist)
		chat.show("%t Установлен " clist "-й клист.")
	}
}
return

escapeCheck:
IfWinNotExist, ahk_exe gta_sa.exe
	settimer, escapeCheck, off

IfWinNotActive, ahk_exe gta_sa.exe
	return

if (CheckHandles() = 1)
	settimer, escapeCheck, off

if GetKeyState("Escape", "P")
	process, close, gta_sa.exe

return

SyncWithgame:
synced = 0
Loop files, SyncWithGame\*, R
{
	synced = 1
	break
}

if synced = 0
	return

synccount = 0
Loop files, SyncWithGame\*, R
	synccount+=1

Loop files, SyncWithGame\*, R
{
	IfWinActive, ahk_id %mainwid%
	{
		if (GetKeyState("Escape", "P")) {
			progressText("Синхронизация файлов отменена.")
			sleep 1000
			return
		}
	}
	
	Gui, 1:+OwnDialogs
	Gui, 1:Default
	
	loopfp = %A_LoopFileFullPath%
	StringReplace, loopfp, loopfp, % A_WorkingDir "\",
	StringReplace, loopfp, loopfp, % "SyncWithGame\",
	SplitPath, loopfp,, loopfp_dir
	FileCreateDir, %gamepath%\%loopfp_dir%
	
	console.writeln("SYNC | File Sync Process: " gamepath "\" loopfp "...")
	progressText("Синхронизация файлов... (" round(percent(A_Index, synccount)) "%)")
	FileDelete, %gamepath%\%loopfp%
	FileCopy, %A_LoopFileFullPath%, %gamepath%\%loopfp%
	ifnotexist, %gamepath%\%loopfp%
		MsgBox, 16, % title, % "Ошибка копирования: " gamepath "\" loopfp "."
}

progressText("Синхронизация файлов завершена.")
progressText("Удаление файла: VehicleAudioData.ini...")
filedelete, %gamepath%\VehicleAudioData.ini

progressText("Удаление файла: vehicleaudioloader.asi...")
filedelete, %gamepath%\vehicleaudioloader.asi

Gui, SyncWithGame:Destroy
return

chatlogger:
IfWinNotActive, ahk_exe gta_sa.exe
	return

ifnotexist, % path_chatlog
	return

if zanes = 0
	return

text_in_chatlog := GetChatLine(0)

if game_loaded = 0
{
	If (findChatLine("Добро пожаловать на GTA RolePlay")) {
		ghtruck.dropAll()
		game_loaded = 1
		is_authed = 0
		sleep 1100
		game_loaded = 1
		sleep 5000
		printlow("GOS Helper was connected.", 1500)
		sleep 5000
		if !owc
		{
			console.writeln("Creating overlay... game_loaded=" game_loaded)
			overlay.create()
			
			sleep 1000
			if ((is_sub) & (afktime))
				overlay.createAFK()
			
			if (ov_allow_support) {
				overlay.createSupport()
			}
		
			if ((afk_overlay_id = -1) || (overlay_id = -1)) {
				chat.show(msg_overlay_error1)
				chat.show(msg_overlay_error2)
			}
		
			owc = 1
		}
	}
}

if (ov_allow_support) {
	indexxx = -1
	loop, 20
	{
		indexxx+=1
		questions_sup1 := ""
		chatloggg := GetChatLine(indexxx, 1)
		RegExMatch(chatloggg, "i)Вопрос от (.*)\[(.*)\]\: (.*)", questions_sup)
		if questions_sup1
		{
			cld(chatloggg)
			ssupport_questions_ov :=  ""
			support_questions_ov := chatloggg "`n" support_questions_ov
			loop, parse, support_questions_ov, `n
			{
				ssupport_questions_ov := ssupport_questions_ov "{CC9900}" A_LoopField "`n"
				
				if A_Index > 5
					break
			}
			
			loop, parse, ssupport_questions_ov, `n
			{
				if A_Index = 1
					TextSetString(sup_overlay_id1, str.left(A_LoopField, 100))
				
				if A_Index = 2
					TextSetString(sup_overlay_id2, str.left(A_LoopField, 100))
				
				if A_Index = 3
					TextSetString(sup_overlay_id3, str.left(A_LoopField, 100))
				
				if A_Index = 4
					TextSetString(sup_overlay_id4, str.left(A_LoopField, 100))
				
				if A_Index = 5
					TextSetString(sup_overlay_id5, str.left(A_LoopField, 100))
				
				if A_Index > 5
					break
			}
			
			SoundBeep, 200, 500
			break
		}
		
		RegExMatch(chatloggg, "i)Вопрос от (.*)\[(.*)\] \[VIP\]\: (.*)", questions_sup)
		if questions_sup1
		{
			cld(chatloggg)
			ssupport_questions_ov :=  ""
			support_questions_ov := chatloggg "`n" support_questions_ov
			loop, parse, support_questions_ov, `n
			{
				ssupport_questions_ov := ssupport_questions_ov "{CC9900}" A_LoopField "`n"
				
				if A_Index > 5
					break
			}
			
			loop, parse, ssupport_questions_ov, `n
			{
				if A_Index = 1
					TextSetString(sup_overlay_id1, str.left(A_LoopField, 100))
				
				if A_Index = 2
					TextSetString(sup_overlay_id2, str.left(A_LoopField, 100))
				
				if A_Index = 3
					TextSetString(sup_overlay_id3, str.left(A_LoopField, 100))
				
				if A_Index = 4
					TextSetString(sup_overlay_id4, str.left(A_LoopField, 100))
				
				if A_Index = 5
					TextSetString(sup_overlay_id5, str.left(A_LoopField, 100))
				
				if A_Index > 5
					break
			}
			
			SoundBeep, 100, 500
			break
		}
	}
}

if (supportresps) {
	axxxxxx := findChatLine("< SUPPORT-PM: ", 100, 0)
	RegExMatch(axxxxxx, "i)\< SUPPORT-PM\: (.*)\_(.*)\[(.*)\] игроку (.*) > (.*)", outat)
	if (outat1) {
		pm_nickname := outat1 "_" outat2
		if (playername = pm_nickname) {
			IniRead, supportresp_count, config.ini, game, supportresp_count
			supportresp_count+=1
			IniWrite, % supportresp_count, config.ini, game, supportresp_count
			
			printlow("GH PM RESPONDED: " supportresp_count, 1000)
			cld(axxxxxx)
			return
		}
	}
}

if (autotazer) {
	RegExMatch(findChatLine("Вы ударили электрошокером игрока "), "i)Вы ударили электрошокером игрока (.*)", outat)
	if (outat1) {
		cld(findChatLine("Вы ударили электрошокером игрока "))
		RegExMatch(fraction, "(.*) ((.*))", fraction)
		fraction2 := StrReplace(StrReplace(fraction2, "("), ")")
		
		ifnotexist, binders\%fraction2%\куфы.ini
		{
			chat.show("%t Автокуфы недоступны для Вашей фракции.")
			return
		}
		
		if (chat.getQueueTime() > 3000) {
			cld(A_LoopField)
			chat.show("%t Очередь сообщений переполнена. Ударьте игрока еще раз.")
			sleep 1000
			return
		}
		
		chat.send("/id " outat1, 1)
		sleep 1200
		
		index := 0, ms := 0
		loop {
			sleep 1
			haystack := GetChatLine(index)
			RegExMatch(haystack, "Игрок (.*)\_(.*)\[(.*)\]", pname)
			
			autotazer_name := pname1
			autotazer_family := pname2
			autotazer_id := pname3
			index++
			ms+=1
			
			if autotazer_name
				break
			
			if (ms > 500) {
				chat.show("%t Не найдена информация об игроке. Операция отменена.")
				chat.show("%t Проверьте, может какие-нибудь программы не дают доступ к чатлогу.")
				settimer, chatlogger, on
				return
			}
		}
		
		dynamicbtext_name := autotazer_name
		dynamicbtext_family := autotazer_family
		dynamicbtext_id := autotazer_id
		
		cld(A_LoopField)
		gosub _куфы
		return
	}
}

if (isPlayerInAnyVehicle()) {
	RegExMatch(findChatLine("Вы арендовали грузовик за "), "Вы арендовали грузовик за (.*) руб.", outtruck)
	if (outtruck1) {
		sleep 250
		if findChatLine("Чтобы начать перевозки, загрузитесь {FFFFFF}(( /gps >> Дальнобойщики ))")
		{
			ghtruck.rent(outtruck1)
			chat.show("%t Записано в статистику для дальнобойщиков (%b/ghtruck%w).")
		}
		cld(findChatLine("Вы арендовали грузовик за "))
		return
	}
	
	RegExMatch(findChatLine("Вы загрузили "), "Вы загрузили (.*) тонн нефти за (.*) рублей", outtruck)
	if (outtruck1) {
		sleep 250
		if findChatLine("Возьмите прицеп и двигайтесь к месту сдачи (( /gps >> Дальнобойщики ))")
		{
			ghtruck.loadCargo(outtruck2)
			chat.show("%t Записано в статистику для дальнобойщиков (%b/ghtruck%w).")
		}
		cld(findChatLine("Вы загрузили "))
		return
	}
	
	RegExMatch(findChatLine("Вы загрузили "), "Вы загрузили (.*) тонн Coca-Cola за (.*) рублей", outtruck)
	if (outtruck1) {
		sleep 250
		if findChatLine("Возьмите прицеп и двигайтесь к месту сдачи (( /gps >> Дальнобойщики ))")
		{
			ghtruck.loadCargo(outtruck2)
			chat.show("%t Записано в статистику для дальнобойщиков (%b/ghtruck%w).")
		}
		cld(findChatLine("Вы загрузили "))
		return
	}
	
	RegExMatch(findChatLine("Вы разгрузили "), "Вы разгрузили (.*) тонн нефти за (.*) рублей", outtruck)
	if (outtruck1) {
		ghtruck.unloadCargo(outtruck2)
		chat.show("%t Записано в статистику для дальнобойщиков (%b/ghtruck%w).")
		cld(findChatLine("Вы разгрузили "))
		return
	}
	
	RegExMatch(findChatLine("Вы разгрузили "), "Вы разгрузили (.*) тонн Coca-Cola за (.*) рублей", outtruck)
	if (outtruck1) {
		ghtruck.unloadCargo(outtruck2)
		chat.show("%t Записано в статистику для дальнобойщиков (%b/ghtruck%w).")
		cld(findChatLine("Вы разгрузили "))
		return
	}
}

if autorem
{
	If (findChatLine("Вы пострадали в ДТП, пристегните ремень безопасности")) {
		chat.send("/rem")
		cld(findChatLine("Вы пострадали в ДТП, пристегните ремень безопасности"))
		return
	}
}

if sortscreenstate
{
	RegExMatch(findchatline("Скриншот сохранен "), "i)Скриншот сохранен (.*)", outt)
	if outt1
	{
		cld(findchatline("Скриншот сохранен "))
		_sortscreenstate:
		Loop, parse, outt1, % A_Space
		{
			filename := A_LoopField
			break
		}
	
		if (sortscreen_to) {
			loop, parse, sortscreen_to, `|
			{
				if A_Index = 1
					sortscreen_folder := A_LoopField
				
				if A_Index = 2
					sortscreen_name := A_LoopField
			}
			
			sortscreen_to := ""
			FileCreateDir, %path_screens%\GOS Helper\%sortscreen_folder%
			
			ifnotexist, %path_screens%\GOS Helper\%sortscreen_folder%\%sortscreen_name%.png
			{
				FileMove, %path_screens%\%filename%, %path_screens%\GOS Helper\%sortscreen_folder%\%sortscreen_name%.png
				chat.show("%t Скриншот автоматически перенесен в папку '%bGOS Helper\" sortscreen_folder "%w' в папке скриншотов.")
			}
			else {
				loop {
					ifexist, %path_screens%\GOS Helper\%sortscreen_folder%\%sortscreen_name% (%A_Index%).png
						continue
					
					FileMove, %path_screens%\%filename%, %path_screens%\GOS Helper\%sortscreen_folder%\%sortscreen_name% (%A_Index%).png
					chat.show("%t Скриншот автоматически перенесен в папку '%bGOS Helper\" sortscreen_folder "%w' в папке скриншотов.")
					break
				}
			}
			
			return
		}
		
		find_folders := 0, find_folders_list := ""
		loop files, %path_screens%\GOS Helper\*, D
			find_folders := find_folders + 1, find_folders_list := find_folders_list A_LoopFileName ","
		
		if find_folders = 0
		{
			chat.show("%t В папке скриншотов игры откройте папку 'GOS Helper'. В ней создайте папки, например: РП, лекции и т.п.")
			return
		}
		
		tmp_text_folders = Введите номер папки`, куда нужно переместить скриншот.`n
		loop, parse, find_folders_list, `,
		{
			if !A_LoopField
				continue
			
			tmp_text_folders := tmp_text_folders A_Index ". " A_LoopField "`n", tmp_folders_list := tmp_folders_list A_Index " -.- " A_LoopField "`n"
		}
		
		tmp_text_folders := tmp_text_folders "`nНужно указать именно число."
		move_folder_number := chat.input(tmp_text_folders)
		if move_folder_number = -1
			return
		
		move_folder_number := Trim(move_folder_number)
		if !move_folder_number
		{
			chat.show("%t Нужно указать целое число.")
			goto _sortscreenstate
		}
		
		loop, parse, tmp_folders_list, `n
		{
			RegExMatch(A_LoopField, "(.*) -.- (.*)", outtmp)
			if outtmp1
			{
				if A_Index = %move_folder_number%
				{
					loop {
						ifexist, %path_screens%\GOS Helper\%outtmp2%\%A_Index%.png
							continue
						
						FileMove, %path_screens%\%filename%, %path_screens%\GOS Helper\%outtmp2%\%A_Index%.png
						chat.show("%t Скриншот перемещен в папку " outtmp2 " с названием " A_Index ".png.")
						return
					}
				}
			}
		}
		
		goto _sortscreenstate
		return
	}
}

;;;;;;;;;;;;;;;;;;;;;;;;;; === Отыгровки для фракции === ;;;;;;;;;;;;;;;;;;;;;;;;;;

RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")
return

Delete_Settings_Autogunrp:
Gui, autogunrp:+OwnDialogs
MsgBox, 49, % title, Все ваши настройки автоматических отыгровок оружия будут заменены на стандартные.
IfMsgBox, Cancel
	return

FileDelete, gunrp.ini
checkconfig()

gosub settings_autogunrp
return

_cmd_antipause:
antipause()
chat.show("%t Теперь если Вы свернете игру, то она не будет на паузе.")
return

_cmd_setweather:
RegExMatch(chatInput, "i)/setweather (.*)", weather_id)
weather_id := weather_id1

setweather(weather_id)
chat.show("%t Установлена погода: " weather_id ".")
return

_cmd_motionblur:
RegExMatch(chatInput, "i)/motionblur (.*)", motion_blur)
motion_blur := motion_blur1

if (motion_blur != 0) & (motion_blur != 1) {
	chat.show("%t Укажите либо '1' (включить), либо '0' (выключить).")
	return
}

motion_blur := Round(motion_blur)
toggleMotionBlur(motion_blur)

if motion_blur = 1
	chat.show("%t Вы включили размытость при движении на большой скорости.")

if motion_blur = 0
	chat.show("%t Вы выключили размытость при движении на большой скорости.")

return

:?:/mem::
SendInput, /members
KeyWait, Enter, U
return

:?:/mmtime::
SendInput, /militarytime
KeyWait, Enter, U
return

:?:/mtime::
SendInput, /mutetime
KeyWait, Enter, U
return

:?:/wh::
SendInput, /warehouse
KeyWait, Enter, U
return

:?:/n::
SendInput, /b
KeyWait, Enter, U
return

:?:/ff::
SendInput, /family
KeyWait, Enter, U
return

:?:/rr::
SendInput, /rb
KeyWait, Enter, U
return

:?:/dd::
SendInput, /db	
KeyWait, Enter, U
return

_cmd_abbrev:
tmp_text =
(
{4169E1}/mem {FFFFFF}- заменит на /members.
{4169E1}/mmtime {FFFFFF}- заменит на /militarytime.
{4169E1}/mtime {FFFFFF}- заменит на /mutetime.
{4169E1}/wh {FFFFFF}- заменит на /warehouse.
{4169E1}/n {FFFFFF}- заменит на /b.
{4169E1}/rr {FFFFFF}- заменит на /rb.
{4169E1}/dd {FFFFFF}- заменит на /db.
{4169E1}/ff {FFFFFF}- заменит на /family.
{4169E1}/finv {FFFFFF}- заменит на /ffinvite.
{4169E1}/funinv {FFFFFF}- заменит на /ffuninvite
)

showDialog(0, "{4169E1}" title, tmp_text, "Закрыть", Button2 := "", Id := 1)
return

; =============================================================================

_cmd_qvm: ; quick vk message
if (vkmsg_state != 1)
	return

if (!sender_virt_id)
{
	chat.show("{4169E1}[VKMSG]{FFFFFF} Вам еще никто не написал.")
	return
}

if (vkmsg_peer_type != "user")
{
	chat.show("{4169E1}[VKMSG]{FFFFFF} Вы можете ответить только пользователю.")
	return
}

qvm_moment_name := vkmsg_profile_name
qvm_moment_family := vkmsg_profile_family
qvm_moment_sender_virt_id := sender_virt_id
qvm_moment_vkmsg_peer_id := vkmsg_peer_id

qvm_msg_text := chat.input("Вы отправите сообщение для {4169E1}" qvm_moment_name " " qvm_moment_family " {FFFFFF}(id" qvm_moment_sender_virt_id ").`nВы можете написать сообщение в ответ ниже.")
if qvm_msg_text = -1
	return

reply_id := qvm_moment_sender_virt_id
reply_text := qvm_msg_text
goto _qvm

_cmd_vreply:
if (vkmsg_state != 1)
	return

RegExMatch(chatInput, "i)/vreply (.*)", vkmsg_params)
vkmsg_params := vkmsg_params1

if (!_vkmsg.id(vkmsg_params)) {
	chat.show("{4169E1}[VKMSG] {FFFFFF}Пользователь с вирт. идентификатором {4169E1}" vkmsg_params "{FFFFFF} не найден.")
	return
}

qvv_moment_name := _vkmsg.firstName(vkmsg_params)
qvv_moment_family := _vkmsg.lastName(vkmsg_params)
qvv_moment_sender_virt_id := vkmsg_params
qvv_moment_vkmsg_peer_id := _vkmsg.id(vkmsg_params)

goto _qvv
return

_cmd_qvv:
if (vkmsg_state != 1)
	return

if (!sender_virt_id)
{
	chat.show("{4169E1}[VKMSG]{FFFFFF} Вам еще никто не написал.")
	return
}

if (vkmsg_peer_type != "user")
{
	chat.show("{4169E1}[VKMSG]{FFFFFF} Вы можете ответить только пользователю.")
	return
}

qvv_moment_name := vkmsg_profile_name
qvv_moment_family := vkmsg_profile_family
qvv_moment_sender_virt_id := sender_virt_id
qvv_moment_vkmsg_peer_id := vkmsg_peer_id

_qvv:
sendvm = 0
chat.show("{4169E1}[VKMSG]{FFFFFF} Вы запишите сообщение для " qvv_moment_name " " qvv_moment_family " (id" qvv_moment_sender_virt_id ").")
chat.show("{4169E1}[VKMSG]{FFFFFF} Удерживайте Alt для записи голосового сообщения.")
KeyWait, Alt, D T5
if (!GetKeyState("Alt", "P")) {
	chat.show("%t Превышено время ожидания действия пользователя. Запись аудиосообщения не будет.")
	return
}

FileDelete, %A_Temp%\gh_voice.wav
VoiceRecord()
chat.show("{4169E1}[VKMSG]{FFFFFF} Говорите! Запись аудиосообщения...")
KeyWait, Alt, U
VoiceRecord("stop", A_Temp "\gh_voice.wav")
chat.show("{4169E1}[VKMSG]{FFFFFF} Отлично! Запись аудиосообщения завершена. Длительность: {4169E1}" FormatSeconds(GetAudioDuration(A_Temp "\gh_voice.wav")/1000) "{FFFFFF}.")
chat.show("{4169E1}[VKMSG]{FFFFFF} Чтобы прослушать сообщение, используйте {4169E1}/playvm{FFFFFF}, а для его отправки {4169E1}/sendvm{FFFFFF}.")
sendvm = 1
return

_cmd_playvm:
if (vkmsg_state != 1)
	return

IfNotExist, %A_Temp%\gh_voice.wav
	return

chat.show("{4169E1}[VKMSG]{FFFFFF} Прослушивание Вашего голосового сообщения...")
SoundPlay, %A_Temp%\gh_voice.wav, 1
chat.show("{4169E1}[VKMSG]{FFFFFF} Прослушивание завершено.")
return

_cmd_sendvm:
if !sendvm
	return

settimer, vkmsg_loop, off
sleep 333
vk_api("docs.getUploadServer&type=audio_message&v=5.63", token)
try upload_url := api.response.upload_url
catch {
	chat.show("{4169E1}[VKMSG]{FFFFFF} Ошибка: upload_url не обнаружен.")
	return
}

path_to_att = %A_Temp%\gh_voice.wav
CreateFormData(postData, hdr_ContentType, {file: [path_to_att]})
try {
	whr := ComObjCreate("WinHttp.WinHttpRequest.5.1")
	whr.Open("POST", upload_url, false)
	whr.SetRequestHeader("Content-Type", hdr_ContentType)
	whr.Send(postData)
	if (whr.Status != 200)
	{
		chat.show("{4169E1}[VKMSG]{FFFFFF} Ошибка загрузки файла.")
		return
	}
	else {
		responseText := whr.responseText
		for k, v in ["server", "photos_list", "aid", "hash"]
		%v% := StrReplace(JS.("JSON.parse('" . StrReplace(responseText, "\""", "|") . "')." . v), "|", """")
	}
}

;{"file":"342065889|0|-1|848128|8fb24bb7ab|pdf|926898|\u0438\u043d\u0441\u0442\u0440\u0443\u043a\u0446\u0438\u044f CITIZEN SDC-888TII.pdf|78e2a1c3249855624c19ad2cdd40c5af|2c2a0703e546f111c9f8d82d09105168||||eyJkaXNrIjoiMTcifQ=="}

try JSON := responseText
try htmldoc := ComObjCreate("htmlfile")
try Script := htmldoc.Script
try Script.execScript(" ", "JScript")
try api := Script.eval("(" . JSON . ")")
catch {
	chat.show("{4169E1}[VKMSG]{FFFFFF} Ошибка преобразования JSON ответа в объект.")
}

try file := api.file
catch {
	chat.show("{4169E1}[VKMSG]{FFFFFF} Ошибка: api.file не найден.")
	return
}

vk_api("docs.save&file=" file "&title=voice_msg.mp3", token)
;{"response":{"type":"doc","doc":{"id":533052700,"owner_id":342065889,"title":"Файл для технической поддержки Streleckiy Launcher.","size":926898,"ext":"pdf","url":"https:\/\/vk.com\/doc342065889_533052700?hash=cbc03e7686ebf48b1c&dl=GM2DEMBWGU4DQOI:1577716377:6048d7815c62009b67&api=1&no_preview=1","date":1577716377,"type":1}}}

try doc_id := api.response.audio_message.id
try owner_id := api.response.audio_message.owner_id

if (!doc_id) or (!owner_id) {
	chat.show("{4169E1}[VKMSG]{FFFFFF} Ошибка (не определено): doc_id или owner_id.")
	return
}

attachment := "doc" owner_id "_" doc_id
random, rid, 10000, 10000000
vk_api("messages.send&attachment=" attachment "&peer_id=" qvv_moment_vkmsg_peer_id "&random_id=" rid, token)
chat.show("{4169E1}[VKMSG] {FFFFFF}" qvv_moment_name " " qvv_moment_family " получил(а) Ваше сообщение.")
sendvm = 1
sleep 333
settimer, vkmsg_loop, on
return

; =============================================================================

_cmd_quit:
process, close, gta_sa.exe
while game_loaded
	continue

return

_cmd_setnick:
RegExMatch(chatInput, "i)/setnick (.*)", next_nick)
next_nick := next_nick1

RegWrite, REG_SZ, HKEY_CURRENT_USER, SOFTWARE\SAMP, PlayerName, % next_nick
chat.show("%t Теперь при следующем заходе в игру будет указан ник {4169E1}" next_nick "{FFFFFF}.")
reload

_cmd_ul:
_cmd_updatelist:
showDialog(0, "{4169E1}" title, update_list, "Закрыть", Button2 := "", Id := 1)
return

_cmd_dev:
playerhp := round(getPlayerHealth())
playerarmour := round(getPlayerArmour())
playerskin := getPlayerSkinId()
playerweapon := getPlayerWeaponId()
playermoney := getPlayerMoney()
isinafk := isinafk()
IsPlayerFreezed := IsPlayerFreezed()
weatherid := getWeatherID()
getPlayerCoordinates(coords_x, coords_y, coords_z)
getCameraCoordinates(coords_x_cam, coords_y_cam, coords_z_cam)
ovids := overlay_id
ovafkid := afk_overlay_id
RegRead, playername, HKEY_CURRENT_USER, SOFTWARE\SAMP, PlayerName

info_tmp =
(
{FFFFFF}Единицы здоровья игрока:`t`t{4169E1}%playerhp%
{FFFFFF}Единицы брони игрока:`t`t{4169E1}%playerarmour%
{FFFFFF}Скин игрока:`t`t`t`t{4169E1}%playerskin%
{FFFFFF}Ник игрока (на русском):`t`t{4169E1}%rusnick%
{FFFFFF}Ник игрока (с игры):`t`t`t{4169E1}%PlayerName%

{FFFFFF}Координата X игрока:`t`t`t{4169E1}%coords_x%
{FFFFFF}Координата Y игрока:`t`t`t{4169E1}%coords_y%
{FFFFFF}Координата Z игрока:`t`t`t{4169E1}%coords_z%

{FFFFFF}Координата X камеры:`t`t{4169E1}%coords_x_cam%
{FFFFFF}Координата Y камеры:`t`t{4169E1}%coords_y_cam%
{FFFFFF}Координата Z камеры:`t`t{4169E1}%coords_z_cam%

{FFFFFF}Оверлей (ID):`t`t`t`t{4169E1}%ovids%
{FFFFFF}Оверлей AFK (ID):`t`t`t{4169E1}%ovafkid%
{FFFFFF}dwSamp:`t`t`t`t{4169E1}%dwSamp%

{FFFFFF}Погода (ID):`t`t`t`t{4169E1}%weatherid%
{FFFFFF}Игрок заморожен:`t`t`t{4169E1}
)

if IsPlayerFreezed = 1
	info_tmp = %info_tmp%Да
else
	info_tmp = %info_tmp%Нет

dialog.standard(info_tmp)
return

_cmd_devdwsamp:
clipboard := dwSamp
chat.show("%t OK!")
return

_cmd_devreload:
goto reload

checkFractions:
cf_finded = 0
loop, parse, fraclist, `|
{
	if (fraction = A_LoopField)
		cf_finded = 1
}

if cf_finded = 0
	fraction := ""

return

aboutme:
Gui, Aboutme:Destroy
Gui, Aboutme:-MinimizeBox +hwndaboutmewid +AlwaysOnTop
Gui, Aboutme:color, White
Gui, Aboutme:Font, S11 CDefault Bold, Segoe UI
Gui, Aboutme:Add, Text,, Информация о Вас
Gui, Aboutme:Font, S9 CDefault norm, Segoe UI
Gui, Aboutme:Add, Text, xs, Укажите Ваш Ник на русском языке (напр. Иван_Иванов)
Gui, Aboutme:Add, Edit, vrusnick w250, % rusnick
Gui, Aboutme:Add, Text,, Укажите Вашу организацию
Gui, Aboutme:Add, ComboBox, vFraction w250, % fraclist
Gui, Aboutme:Add, Text,, Укажите Ваше звание (напр. Матрос)
Gui, Aboutme:Add, Edit, vrang w250, % rang
Gui, Aboutme:Add, Text,, Укажите Ваш номер тел. в игре
Gui, Aboutme:Add, Edit, vnumber w250, % number
Gui, Aboutme:Add, Text,, Укажите Ваш тег (напр. Гл.С)
Gui, Aboutme:Add, Edit, vtag w250, % tag
Gui, Aboutme:Add, Text,, Укажите Ваш "номер галстука" (/clist)
Gui, Aboutme:Add, Edit, w250 vclist number, % clist
Gui, Aboutme:Font, S8 CDefault norm, Segoe UI
Gui, Aboutme:Add, Text, cGray, Если у Вас нет тега/галстука`, то оставьте поле пустым.
Gui, Aboutme:Font, S9 CDefault norm, Segoe UI
Gui, Aboutme:Add, Button, gAboutme_SaveAll, Запомнить все
Gui, Aboutme:Show,, % title

ControlSetText, Edit2, % fraction, ahk_id %aboutmewid%

settimer, _aboutmeloop, 10

_aboutmeloop:
IfWinNotExist, ahk_id %aboutmewid%
{
	SetTimer, _aboutmeloop, off
	return
}

IfWinNotActive, ahk_id %aboutmewid%
	return

if GetKeyState("Escape", "P")
	gui, aboutme:destroy

if GetKeyState("Enter", "P")
	goto aboutme_saveall

return

aboutmeguiclose:
Gui, Aboutme:Destroy
return

Aboutme_SaveAll:
Gui, aboutme:submit, nohide
Gui, 1:Default
if !rusnick
{
	Gui, Aboutme:+OwnDialogs
	MsgBox, 16, % title, Вы не указали Ваш ник на русском языке., 10
	return
}

if !fraction
{
	Gui, Aboutme:+OwnDialogs
	MsgBox, 16, % title, Укажите Вашу организацию., 10
	return
}

if !rang
{
	Gui, Aboutme:+OwnDialogs
	MsgBox, 16, % title, Вы не указали Ваш ранг., 10
	return
}

if !number
{
	Gui, Aboutme:+OwnDialogs
	MsgBox, 16, % title, Вы не указали Ваш игровой номер телефона., 10
	return
}

Loop, parse, rusnick, _
{
	if A_Index = 1
	{
		rus_name = %A_LoopField%
		continue
	}
	
	if A_Index = 2
	{
		rus_family = %A_LoopField%
		break
	}
}

if (!rus_name or !rus_family)
{
	Gui, Aboutme:+OwnDialogs
	MsgBox, 16, %title%, Указан недопустимый ник (напишите его по образцу)., 10
	return
}

gosub checkFractions
if !fraction
{
	Gui, Aboutme:+OwnDialogs
	MsgBox, 16, % title, Такой фракции не существует. Выберите фракцию из списка.
	return
}

if (str.CheckLatin(rusnick)) {
	Gui, Aboutme:+OwnDialogs
	MsgBox, 16, %title%, Указан недопустимый ник (напишите его кириллицей)., 10
	return
}

progressText("Запись конфига: секция roleplay, пункт rusnick")
IniWrite, % rusnick, config.ini, Roleplay, rusnick

progressText("Запись конфига: секция roleplay, пункт rang")
IniWrite, % rang, config.ini, Roleplay, rang

progressText("Запись конфига: секция roleplay, пункт tag")
IniWrite, % tag, config.ini, Roleplay, tag

progressText("Запись конфига: секция roleplay, пункт clist")
IniWrite, % clist, config.ini, Roleplay, clist

progressText("Запись конфига: секция roleplay, пункт fraction")
IniWrite, % fraction, config.ini, Roleplay, fraction

progressText("Запись конфига: секция roleplay, пункт number")
IniWrite, % number, config.ini, Roleplay, number

progressText("Все изменения сохранены.")
Gui, aboutme:destroy
return

IfMsgBox, yes
	Run, http://vk.com/strelprog,, UseErrorLevel

return

_autorem:
if !game_loaded
	return

if isPlayerInAnyVehicle()
{
	if remed
		return
	
	waitrem = 1
	remed = 1
	chat.send("/rem")
	waitrem = 0
	return
}

remed = 0
return

open_screen:
Run, %A_MyDocuments%\GTA San Andreas User Files\SAMP\screens,, UseErrorLevel
return

auto_copy:
Run, %A_WorkingDir%\syncwithgame,, UseErrorLevel
Gui, +OwnDialogs

if !autocopyy
	TrayTip, % title, Сюда вы можете переместить файлы (напр. папка клео)`, и они автоматически скопируются в папку игры.

autocopyy = 1
return

_cmd_gh:
showDialog(0, "{4169E1}" title, cmd_list, "Закрыть", Button2 := "", Id := 1)
return

_cmd_vkmsg:
if !token
{
	chat.show("{4169E1}[VKMSG] {FFFFFF}Ошибка. {FFFFFF}Авторизируйтесь ВКонтакте, чтобы работать со сообщениями.")
	return
}

if vkmsg_state = 1
{
	vkmsg_state = 0
	settimer, vkmsg_loop, off
	showDialog(0, "{4169E1}" title, "{FFFFFF}Функция отключена. Новые сообщения больше не будут показываться.", "Закрыть", Button2 := "", Id := 1)
	return
}

tmp_text =
(
{FFFFFF}Функция запущена. Сообщения будут обрабатываться только от пользователей.
Другими словами: беседы, сообщения от сообществ обрабатываться не будут.

Для ответа на сообщение используйте команду {4169E1}/reply <virt. id> <text>{FFFFFF}.
Для ответа на сообщение голосовым сообщением, используйте {4169E1}/vreply <virt. id>{FFFFFF}.
Чтобы открыть диалог в браузере, используйте {4169E1}/opendialog <virt. id>{FFFFFF}.
Чтобы уточнить, какие идентификаторы записаны, используйте {4169E1}/replyids{FFFFFF}.

Чтобы быстро ответить на сообщение, используйте {4169E1}/qvm{FFFFFF} (от сокр. Quick VK Message).
Чтобы быстро ответить на сообщение голосовым сообщением, используйте {4169E1}/qvv{FFFFFF} (от сокр. Quick VK Voice).
)

vkmsg_list_ids = 
vkmsg_state = 1
showDialog(0, "{4169E1}" title, tmp_text, "Закрыть", Button2 := "", Id := 1)

sleep 333
vk_api("users.get", token)
if vkmsg_myid := api.response.0.id
sleep 333

vk_api("messages.getConversations&count=1&extended=1", token)

try vkmsg_peer_type := api.response.items.0.conversation.peer.type
try vkmsg_peer_id := api.response.items.0.conversation.peer.id
try vkmsg_msg_id := api.response.items.0.last_message.id
try vkmsg_msg_text := api.response.items.0.last_message.text
try vkmsg_msg_from_id := api.response.items.0.last_message.from_id

if vkmsg_peer_type = user
{
	try vkmsg_profile_name := api.response.profiles.0.first_name
	try vkmsg_profile_family := api.response.profiles.0.last_name
	try vkmsg_profile_screen_name := api.response.profiles.0.screen_name
}

ovkmsg_msg_id := vkmsg_msg_id

settimer, vkmsg_loop, % calculateLimit(vkapi_limit)
return

vkmsg_loop:
IfWinNotActive, ahk_exe gta_sa.exe
	return

if reply_pls
	return

vk_api("messages.getConversations&count=1&extended=1", token)
vkmsg_msg_voice := "", vkmsg_msg_desc_audio := 0, vkmsg_msg_desc_photo := 0, vkmsg_msg_desc_video := 0, vkmsg_msg_desc_doc := 0, vkmsg_msg_desc_story := 0, vkmsg_msg_desc_gift := 0, vkmsg_msg_desc_gift := 0, vkmsg_msg_attachments_count := 0

loop 10
	vkmsg_msg_attachment_type%A_Index% := ""

try vkmsg_peer_type := api.response.items.0.conversation.peer.type
try vkmsg_peer_id := api.response.items.0.conversation.peer.id
try vkmsg_msg_id := api.response.items.0.last_message.id
try vkmsg_msg_text := api.response.items.0.last_message.text
try vkmsg_msg_from_id := api.response.items.0.last_message.from_id
try vkmsg_msg_voice := api.response.items.0.last_message.attachments.0.audio_message.link_mp3
try vkmsg_msg_fwd_messages1 := api.response.items.0.fwd_messages.0.date
try vkmsg_msg_fwd_messages2:= api.response.items.0.fwd_messages.1.date
vkmsg_msg_text := RegExReplace(vkmsg_msg_text, "Ui)\{[a-f0-9]{6}\}")

try vkmsg_msg_attachment_type1 := api.response.items.0.last_message.attachments.0.type
try vkmsg_msg_attachment_type2 := api.response.items.0.last_message.attachments.1.type
try vkmsg_msg_attachment_type3 := api.response.items.0.last_message.attachments.2.type
try vkmsg_msg_attachment_type4 := api.response.items.0.last_message.attachments.3.type
try vkmsg_msg_attachment_type5 := api.response.items.0.last_message.attachments.4.type
try vkmsg_msg_attachment_type6 := api.response.items.0.last_message.attachments.5.type
try vkmsg_msg_attachment_type7 := api.response.items.0.last_message.attachments.6.type
try vkmsg_msg_attachment_type8 := api.response.items.0.last_message.attachments.7.type
try vkmsg_msg_attachment_type9 := api.response.items.0.last_message.attachments.8.type
try vkmsg_msg_attachment_type10 := api.response.items.0.last_message.attachments.9.type

loop, 10
{
	if vkmsg_msg_attachment_type%A_Index%
		vkmsg_msg_attachments_count++
}

if (ovkmsg_msg_id = vkmsg_msg_id)
	return

try vkmsg_profile_name := api.response.profiles.0.first_name
try vkmsg_profile_family := api.response.profiles.0.last_name

_vkmsg:
if vkmsg_peer_type = user
{	
	if vkmsg_msg_from_id = %vkmsg_myid%
		return
	
	SoundBeep, 100, 100
	sender_virt_id = 0
	index_vkmsg = 0
	finded_vkmsg = 0
	Loop % vkmsg.MaxIndex()
	{
		index_vkmsg++
		if vkmsg[index_vkmsg]
		{
			if (_vkmsg.id(index_vkmsg) = vkmsg_peer_id)
			{
				finded_vkmsg = 1
				sender_virt_id = %index_vkmsg%
				break
			}
		}
	}
	
	if !finded_vkmsg
	{
		vkmsg[vkmsg.MaxIndex()+1] := vkmsg_peer_id "," vkmsg_profile_name "," vkmsg_profile_family
		sender_virt_id := vkmsg.MaxIndex()
		FileAppend, % vkmsg_peer_id "," vkmsg_profile_name "," vkmsg_profile_family "`n", virt_ids.ini
	}
	
	if vkmsg_autoread
		vk_api("messages.markAsRead&mark_conversation_as_read=1&message_ids=" vkmsg_msg_id "&v=5.21", token)
	
	ovkmsg_msg_id := vkmsg_msg_id
	if vkmsg_msg_voice
	{
		if vkmsg_autoplayVoice
		{
			chat.show("{4169E1}[VKMSG] {FFFFFF}Скачиваем и прослушиваем голосовое сообщение от " vkmsg_profile_name " " vkmsg_profile_family " (id" sender_virt_id ").")
			sleep 100
			URLDownloadToFile, % vkmsg_msg_voice, %A_Temp%\gh_voice.mp3
			chat.show("{4169E1}[VKMSG] {FFFFFF}Длительность аудиосообщения: {4169E1}" FormatSeconds(GetAudioDuration(A_Temp "\gh_voice.mp3")/1000) "{FFFFFF}. Для остановки используйте 'End'.")
			Hotkey, End, StopVoice
			Hotkey, End, on
			SoundPlay, %A_Temp%\gh_voice.mp3, 1
			chat.show("{4160E1}[VKMSG] {FFFFFF}Прослушивание сообщения завершено.")
			FileDelete, %A_Temp%\gh_voice.mp3
			return
		}
		
		chat.show("{4169E1}[VKMSG] {FFFFFF}" vkmsg_profile_name " " vkmsg_profile_family " (id" sender_virt_id ") отправила(а) Вам голосовое сообщение.")
		return
	}
	
	if (vkmsg_msg_text = "") {
		if vkmsg_msg_attachments_count = 1
		{
			chat.show("{4169E1}[VKMSG] {FFFFFF}" vkmsg_profile_name " " vkmsg_profile_family " (id" sender_virt_id ") отправила(а) Вам 1 вложение.")
			return
		}
		
		if vkmsg_msg_attachments_count > 1
		{
			chat.show("{4169E1}[VKMSG] {FFFFFF}" vkmsg_profile_name " " vkmsg_profile_family " (id" sender_virt_id ") отправила(а) Вам " vkmsg_msg_attachments_count " вложений.")
			return
		}
		
		chat.show("{4169E1}[VKMSG] {FFFFFF}" vkmsg_profile_name " " vkmsg_profile_family " (id" sender_virt_id ") прислал(а) сообщение.")
		return
	}
	
	if (vkmsg_msg_text != "")
	{
		if (vkmsg_msg_attachments_count = 1)
		{
			chat.show("{4169E1}[VKMSG] {FFFFFF}" vkmsg_profile_name " " vkmsg_profile_family " (id" sender_virt_id ") отправила(а) Вам 1 вложение, со словами: " vkmsg_msg_text)
			return
		}
		
		if (vkmsg_msg_attachments_count > 1)
		{
			chat.show("{4169E1}[VKMSG] {FFFFFF}" vkmsg_profile_name " " vkmsg_profile_family " (id" sender_virt_id ") отправила(а) Вам " vkmsg_msg_attachments_count " вложений, со словами: " vkmsg_msg_text)
			return
		}
		
		chat.show("{4169E1}[VKMSG] {FFFFFF}" vkmsg_profile_name " " vkmsg_profile_family " (id" sender_virt_id ") пишет Вам: " vkmsg_msg_text)
	}
}
return

_cmd_replyids:
if (vkmsg_state != 1)
	return

vkmsgMaxIndex := vkmsg.MaxIndex()

info_tmp := "{FFFFFF}База виртуальных идентификаторов`n "
Loop, % vkmsgMaxIndex
	info_tmp := info_tmp "`n" _vkmsg.firstName(A_Index) " " _vkmsg.lastName(A_Index) " (id: " _vkmsg.id(A_Index) ") вирт. ID: " A_Index "."

if vkmsgmaxindex = 0
{
	chat.show("{4169E1}[VKMSG] {FFFFFF}База виртуальных идентификаторов пуста.")
	return
}

showDialog(2, "{4169E1}" title, info_tmp, "Закрыть", button2 := "", id := "0")
return

_cmd_opendialog:
if (vkmsg_state != 1)
	return

RegExMatch(chatInput, "i)/opendialog (.*)", vkmsg_params)
vkmsg_params := vkmsg_params1

if (!_vkmsg.id(vkmsg_params)) {
	chat.show("{4169E1}[VKMSG] {FFFFFF}Пользователь с вирт. идентификатором {4169E1}" vkmsg_params "{FFFFFF} не найден.")
	return
}

Run, % "http://vk.com/write" _vkmsg.id(vkmsg_params),, UseErrorLevel
if errorlevel
{
	chat.show("{4169E1}[VKMSG] {FFFFFF}Не удалось открыть ссылку в браузере по-умолчанию.")
	return
}

chat.show("{4169E1}[VKMSG] {FFFFFF}Сейчас должна открыться ссылка в браузере по-умолчанию.")
return

_cmd_reply:
if (vkmsg_state != 1)
	return

RegExMatch(chatInput, "i)/reply (.*)", vkmsg_params)
vkmsg_params := vkmsg_params1

reply_id := "", reply_text := ""
Loop, Parse, vkmsg_params, % " "
{
	if A_Index = 1
		reply_id := A_LoopField
	
	if A_Index > 1
		reply_text := reply_text A_LoopField " "
}

if (!reply_id || !reply_text)
{
	chat.show("{4169E1}[VKMSG] {FFFFFF}Синтаксис команды: /reply <цифр. id> <text>")
	return
}

vkmsg_real_user_id = 
vkmsg_virt_id =

_qvm:
if vkmsg[reply_id]
	vkmsg_real_user_id := _vkmsg.id(reply_id)

if !vkmsg_real_user_id
{
	chat.show("{4169E1}[VKMSG] {FFFFFF}ID пользователя не найден.")
	return
}

random, rid, 1, 10000
reply_pls = 1
err_code = 0
vk_api("messages.send&message=" reply_text "&peer_id=" vkmsg_real_user_id "&random_id=" rid, token)
reply_pls = 0

if err_code
	return

chat.show("{4169E1}[VKMSG] {FFFFFF}" _vkmsg.firstName(reply_id) " " _vkmsg.lastName(reply_id) " получил(а) Ваше сообщение.")
return

checkGameLoop:
IfWinNotExist, ahk_exe gta_sa.exe
{
	RegRead, playername, HKEY_CURRENT_USER, SOFTWARE\SAMP, PlayerName
	playername := Trim(playername)
	
	overlay.destroy()
	game_loaded = 0
	gamepid =
	owc = 0
	progressText("Вы вошли как " normalNick ".")
	
	if ghapi_online
	{
		ghapi_online = 0
		server_response := "", server_error := ""
		try DestroyAllVisual()
		started_from_ghlauncher = 0
		return
	}
}

if (CheckHandles()) {
	if injected
		return
	
	if !game_loaded
		return
	
	injected = 1
	progressText("Соединение с игрой успешно. Используйте /gh.")
}
else {
	if !injected
		return
	
	injected = 0
	IfWinExist, ahk_exe gta_sa.exe
		progressText("Потеряно соединение с игрой.")
}
return

healthsys:
if !game_loaded
	return

if armourrp
{
	if (getPlayerArmour() != oldplayerarmour)
	{
		oldplayerarmour := getPlayerArmour()
		if getPlayerArmour() = 100
		{
			chat.send("/me надел(а) бронежилет")
		}
		
		if getPlayerArmour() = 0
		{
			chat.send("/me снял(а) бронежилет")
		}
	}
}

if (getPlayerHealth() < 1) {
	sleep 7000
	if clist
	{
		chat.send("/clist " clist)
		chat.show("%t Установлен " clist "-й клист.")
	}
}

if (!isPlayerInAnyVehicle())
	return

if (getVehicleHealth() < 250) & (getVehicleHealth() > 0) {
	chat.show("%t Критическое здоровье транспорта. Выхожу из него.")
	
	loop {
		ControlSend,, {enter down}, ahk_exe gta_sa.exe
		sleep 500
		ControlSend,, {enter up}, ahk_exe gta_sa.exe
		sleep 1000
		if isPlayerInAnyVehicle() {
			if A_Index > 3
				chat.show("%t%r Не удалось выйти из транспорта! Убедитесь, что кнопка выхода установлена на Enter.")
			
			continue
		}
		
		break
	}
	
	chat.send("/me открыл(а) дверь транспорта и выпрыгнул(а) из нее.")
}
return

ghactivate:
WinShow, ahk_id %mainwid%
WinActivate, ahk_id %mainwid%

loop {
	sleep 1
	wintransp+=40
	WinSet, Transparent, % wintransp, ahk_id %MainWID%
	if wintransp > 255
		break
}
return

vksite:
Run, http://vk.com/strdev,, UseErrorLevel
if errorlevel
	MsgBox, 16, % title, Ошибка открытия страницы: http://vk.com/strdev

return

support:
Gui, Support:Destroy
Gui, Support:-MinimizeBox
Gui, Support:Color, White
Gui, Support:Font, S12 CDefault bold, Segoe UI
Gui, Support:Add, Text, x12 y9 w450 h30 , Обратная связь
Gui, Support:Font, S9 CDefault norm, Segoe UI
Gui, Support:Add, Text, x12 w450 , Если у Вас есть вопросы по работе GOS Helper'a`, то Вы можете задать вопрос напрямую администрации GH.
Gui, Support:Add, Edit, x12 w450 h200 vSupportText limit400, 
Gui, Support:Add, Button, x162 w150 h30 gSupportSend, Отправить
Gui, Support:Show, w479, % title
return

SupportGuiEscape:
gui, Support:Destroy
return

SupportSend:
gui, Support:Submit, NoHide
gui, Support:+OwnDialogs
if (Trim(supportText) = "") {
	MsgBox, 16, % title, Вы не можете отправить пустой тикет.
	return
}

Gui, Support:Destroy
Run, http://vk.com/strdev
return

donate:
Gui, +OwnDialogs
MsgBox, 0, % title, Вы можете пожертвовать деньги/вирты на развитие программы.`n`n- Если Вы пожертвуете от 750.000 вирт`, то Вы будете добавлены в базу данных GH как Меценат. Возможность передачи виртов доступна на всех серверах проекта GTA RolePlay (01`, 02).`n`n- Если Вы пожертвуете от 75 рублей`, то Вы также будете добавлены в базу данных GH как Меценат.`n`nВы можете узнать подробности`, спросив что Вас интересует в Технической Поддержке.
return

vk_new_auth:
Gui, VKAUTH:Destroy
Gui, VKAUTH:+AlwaysOnTop -MinimizeBox +hwndvkauthwid
Gui, VKAUTH:Color, White
Gui, VKAUTH:Font, S11 CDefault Bold, Segoe UI
Gui, VKAUTH:Add, Text, x15 y9 w260 h20 +Center, Авторизация в GOS Helper
Gui, VKAUTH:Font, S9 CDefault norm, Segoe UI
Gui, VKAUTH:Add, Text, x12 y49 w50 h20 , Логин
Gui, VKAUTH:Add, Edit, x72 y49 w210 h20 vVK_LOGIN, 
Gui, VKAUTH:Add, Text, x12 y79 w50 h20 , Пароль
Gui, VKAUTH:Add, Edit, x72 y79 w210 h20 Password vVK_PASSWORD, 
Gui, VKAUTH:Add, Text, x12 y109 w50 h20 , Токен
Gui, VKAUTH:Add, Edit, x72 y109 w210 h20 vToken, 
Gui, VKAUTH:Add, Button, x20 y139 w120 h30 gOpenNewSessionVK vAuthButton, Войти в аккаунт
Gui, VKAUTH:Add, Button, x154 y139 w120 h30 gGetToken vGetToken, Получить токен
Gui, VKAUTH:Show, w295 h186, % title

KeyWait, Enter, U
settimer, vkauthloop, 1

vkauthloop:
IfWinNotExist, ahk_id %vkauthwid%
{
	settimer, vkauthloop, off
	return
}

IfWinNotActive, ahk_id %vkauthwid%
	return

if GetKeyState("Escape", "P")
	Gui, vkauth:destroy

if GetKeyState("Enter", "P")
	gosub opennewsessionvk

MouseGetPos, , , controlwin, Controll, 4

if (controlwin != vkauthwid)
	return

if controll
	ControlFocus, % controll, ahk_id %vkauthwid%

if controlwin != %vkauthwid%
{
	if controlwin != %ocontrolwin%
	{
		ocontrolwin = %controlwin%
		return
	}
}

ocontroll = %controll%

if controll = Edit2
{
	ControlFocus, Edit2, ahk_id %vkauthwid%
	if password_hided = 0
		return
	
	password_hided = 0
	GuiControl, vkauth:-password, VK_PASSWORD
	ToolTip, Уберите мышь от поля для ввода пароля`, для того чтобы его скрыть.
}
else {
	if password_hided = 1
		return
	
	password_hided = 1
	GuiControl, vkauth:+password, VK_PASSWORD
	ToolTip
}
return

OpenNewSessionVK:
ToolTip
GuiControl, vkauth:disable, AuthButton
Gui, VKAUTH:submit, nohide
if token
{
	error_code = 0
	vk_api("users.get&fields=screen_name", token)
	try error_code := api.error.error_code
	if error_code = 5
	{
		Gui, VKAUTH:+OwnDialogs
		MsgBox, 16, % title, Токен не действителен., 3
		KeyWait, Enter, U
		GuiControl, vkauth:enable, AuthButton
		return
	}
	
	vk_api("messages.getHistory&peer_id=-195174479&count=1", token)
	try error_code := api.error.error_code
	if error_code = 15
	{
		Gui, VKAUTH:+OwnDialogs
		MsgBox, 16, % title, Указанный Вами токен не имеет доступа к сообщениям. Доступ к сообщениям необходим для функции VKMSG.
		KeyWait, Enter, U
		GuiControl, vkauth:enable, AuthButton
		return
	}
	
	goto vk_success_auth
	return
}

if (!vk_login || !vk_password) {
	Gui, VKAUTH:+OwnDialogs
	MsgBox, 16, % title, Введите логин и пароль или токен.
	KeyWait, Enter, U
	GuiControl, vkauth:enable, AuthButton
	return
}

Gui, VKAUTH:+OwnDialogs
StringReplace, VK_PASSWORD, VK_PASSWORD, % " ", `+, All
StringReplace, VK_PASSWORD, VK_PASSWORD, % "%", `%25, All
StringReplace, VK_PASSWORD, VK_PASSWORD, % "&", `%26, All

try whr := ComObjCreate("WinHttp.WinHttpRequest.5.1")
try whr.Open("POST", "https://oauth.vk.com/token?grant_type=password&client_id=2274003&client_secret=hHbZxrka2uZ6jB1inYsH&username=" VK_LOGIN "&password=" VK_PASSWORD "&v=5.103&2fa_supported=0" captcha_to_request, true)

if captcha_to_request
	captcha_to_request =

try whr.SetRequestHeader("User-Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36")
try whr.SetRequestHeader("Content-Type","application/x-www-form-urlencoded")
try whr.Send()
try whr.WaitForResponse()
try response := whr.ResponseText
catch {
	MsgBox, 16, % title, % "Не удалось получить ответ сервера.", 3
	KeyWait, Enter, U
	GuiControl, vkauth:enable, AuthButton
	return
}

try JSON = %response%
try htmldoc := ComObjCreate("htmlfile")
try Script := htmldoc.Script
try Script.execScript(" ", "JScript")
try api := Script.eval("(" . JSON . ")")
catch {
	MsgBox, 16, % title, % "Ошибка преобразования JSON ответа в объект: " response ".", 10
	KeyWait, Enter, U
	GuiControl, vkauth:enable, AuthButton
	return
}

try err_text := api.error
if (err_text = "need_captcha")
{
	try captcha_sid := api.captcha_sid
	try captcha_img := api.captcha_img

	captcha_to_request := "&captcha_sid=" captcha_sid "&captcha_key=" captcha(captcha_img)
	goto OpenNewSessionVK
}

error_description =
try error_description := api.error_description
if error_description
{
	if error_description contains sms sent
		2fa = 1
	
	if error_description contains redirect_uri
		2fa = 1
	
	if 2fa
	{
		redirect_uri := api.redirect_uri
		try ie := ComObjCreate("InternetExplorer.Application")
		catch {
			iecrash = 1
		}
		try ie.toolbar := false
		catch {
			iecrash = 1
		}
		try ie.visible := false
		catch {
			iecrash = 1
		}
		try ie.navigate(redirect_uri)
		catch {
			iecrash = 1
		}
		
		if iecrash = 1
		{
			MsgBox, 16, % title, Произошла ошибка при создании объекта. Убедитесь`, что у Вас установлен и обновлен Internet Explorer`, а также не имеется поврежденных файлов.
			KeyWait, Enter, U
			GuiControl, vkauth:enable, AuthButton
			return
		}
		
		loop {
			try ie_readystate := ie.ReadyState
			catch {
				Gui, VKAUTH:+OwnDialogs
				MsgBox, 16, % title, Ошибка получения статуса браузера.
				KeyWait, Enter, U
				GuiControl, vkauth:enable, AuthButton
				return
			}
			
			if ie_readystate = 4
				break
		}
		
		try ie.visible := true
		WinGet, ieid, ID, ahk_class IEFrame
		gui.setprogresstext("Ожидание действий пользователя...")
		loop {
			IfWinNotExist, ahk_id %ieid%
			{
				GuiControl, vkauth:enable, AuthButton
				return
			}
			
			ControlGetText, ielink, Edit1, ahk_id %ieid%
			if ielink contains access_token=
			{
				RegExMatch(ielink, "https://oauth.vk.com/blank.html#success=1&access_token=(.*)&user_id=(.*)", out)
				if out1
				{
					token := out1
					break
				}
			}
		}
		
		Process, close, iexplore.exe
		goto vk_success_auth
	}
	
	Gui, VKAUTH:+OwnDialogs
	MsgBox, 16, %title%, %error_description%., 5
	KeyWait, Enter, U
	GuiControl, vkauth:enable, AuthButton
	return
}

try token := api.access_token
if token	
	goto vk_success_auth

MsgBox, 16, % title, Неизвестная ошибка.
KeyWait, Enter, U
GuiControl, vkauth:enable, AuthButton
return

vk_success_auth:
err_code = 0
vk_api("users.get&fields=screen_name", token)
try first_name := api.response.0.first_name
try last_name := api.response.0.last_name

if err_code
{
	MsgBox, 16, % title, Авторизация не удалась.
	KeyWait, Enter, U
	GuiControl, vkauth:enable, AuthButton
	return
}

Gui, vkauth:Destroy
Gui, 1:+OwnDialogs
IniWrite, % token, config.ini, vkauth, token
gosub _generateVK_Menu
MsgBox, 64, % title, Отлично. Авторизация успешна. Вы вошли под именем %first_name% %last_name%.
KeyWait, Enter, U
GuiControl, vkauth:enable, AuthButton
reload
return

exitSession:
Gui, 1:+owndialogs
MsgBox, 36, % title, Желаете выйти из аккаунта?
IfMsgBox, no
	return

IniWrite, % "", config.ini, vkauth, token
reload

GetToken:
GuiControl, vkauth:disabled, GetToken
gui, +owndialogs
MsgBox, 65, % title, Ссылка "http://vkhost.github.io/" откроется в браузере по-умолчанию.
IfMsgBox, Cancel
{
	GuiControl, vkauth:enabled, GetToken
	return
}

Run, % "http://vkhost.github.io/",, UseErrorLevel
if errorlevel
{
	MsgBox, 16, % title, Ошибка при старте браузера.
	GuiControl, vkauth:enabled, GetToken
	return
}

GuiControl, vkauth:enabled, GetToken
return

GuiClose:
wintransp = 255

loop {
	sleep 1
	wintransp-=40
	WinSet, Transparent, % wintransp, ahk_id %MainWID%
	if wintransp < 1
		break
}

if (!gh_loaded)
	exitapp

if GetKeyState("Escape", "P")
	exitapp

WinHide, ahk_id %mainwid%

if (exit_msg) {
	return
}

if (!traymsg) {
	TrayTip, % title, Программа находится в трее. Нажмите ЛКМ по иконке`, чтобы вернуть окно.
	traymsg = 1
}
return

GuiMinimize:
wintransp = 255

loop {
	sleep 1
	wintransp-=40
	WinSet, Transparent, % wintransp, ahk_id %MainWID%
	if wintransp < 1
		break
}

if (!gh_loaded)
	exitapp

if GetKeyState("Escape", "P")
	exitapp

WinHide, ahk_id %mainwid%
return

Autoregister:
guicontrol, autoregister:disabled, autoregister
sleep 250
gui, autoregister:submit, nohide

if autoregister
{
	IniWrite, 1, config.ini, Autoregister, state
	RegExMatch(fraction, "(.*) ((.*))", autoregister_choosed)
	autoregister_choosed := StrReplace(StrReplace(autoregister_choosed2, "("), ")")
	autoregister = 1
}
else {
	IniWrite, 0, config.ini, Autoregister, state
	autoregister = 0
}

guicontrol, autoregister:enabled, autoregister
return

ARImgur:
guicontrol, autoregister:disabled, arimgur
sleep 250
gui, autoregister:submit, nohide

IniRead, AutoregisterFormatText, config.ini, Autoregister, formatText

if arimgur
{
	if AutoregisterFormatText not contains `$imgur
	{
		Control, Uncheck,, Button2, ahk_id %autoregisterwid%
		MsgBox, 0, % title, В формате записи не участвует переменная $imgur. Включать эту функцию без этой переменной без толку.
		guicontrol, autoregister:enabled, arimgur
		return
	}
	
	IniWrite, 1, config.ini, Autoregister, arimgur
	arimgur = 1
}
else {
	IniWrite, 0, config.ini, Autoregister, arimgur
	arimgur = 0
}

guicontrol, autoregister:enabled, arimgur
return

arsavescreens:
guicontrol, autoregister:disabled, arsavescreens
sleep 250
gui, autoregister:submit, nohide

if !arsavescreens
{
	IniWrite, 0, config.ini, Autoregister, arsavescreens
	arsavescreens = 0
}
else {
	IniWrite, 1, config.ini, Autoregister, arsavescreens
	arsavescreens = 1
}

guicontrol, autoregister:enabled, arsavescreens
return

Autoregister_EditRank:
IniRead, AutoregisterRankListEditing, config.ini, autoregister, rankList%autoregister_choosed%

Gui, autoregister_edit:Destroy
Gui, autoregister_edit:-SysMenu +AlwaysOnTop +hwndautoregister_editwid
Gui, autoregister_edit:Color, White
Gui, autoregister_edit:Font, S11 CDefault bold, Segoe UI
Gui, autoregister_edit:Add, Text, x12 y9 h20 , Настройка названий рангов в автореестре
Gui, autoregister_edit:Font, S9 CDefault norm, Segoe UI
Gui, autoregister_edit:Add, Text, x12 h20, Ранги идут по порядку`, запятая разделяет названия друг от друга.
Gui, autoregister_edit:Add, Edit, x12 h20 w450 vAutoregisterRankListEditing, % AutoregisterRankListEditing
Gui, autoregister_edit:Add, Button, gSaveAutoregisterEditRank, Применить
Gui, autoregister_edit:Show,, % title
return

SaveAutoregisterEditRank:
gui, autoregister_edit:submit
IniWrite, % AutoregisterRankListEditing, config.ini, autoregister, ranklist%autoregister_choosed%
AutoregisterRankList%autoregister_choosed% := AutoregisterRankListEditing
return

AutoregisterButtonEdit:
Gui, autoregister:submit, nohide
autoregister_choosed := ""

RegExMatch(fraction, "(.*) ((.*))", autoregister_choosed)
autoregister_choosed := StrReplace(StrReplace(autoregister_choosed2, "("), ")")

fileread, autoregister_invite_text, autoregister\%autoregister_choosed%\invite.ini
fileread, autoregister_uninvite_text, autoregister\%autoregister_choosed%\uninvite.ini
fileread, autoregister_giverank_text, autoregister\%autoregister_choosed%\giverank.ini

if autoregister_choosed = FBI
{
	fileread, autoregister_funinvite_text, autoregister\%autoregister_choosed%\funinvite.ini
	fileread, autoregister_fgiverank_text, autoregister\%autoregister_choosed%\fgiverank.ini
}

Gui, autoregister_edit:Destroy
Gui, autoregister_edit:-SysMenu +AlwaysOnTop +hwndautoregister_editwid
Gui, autoregister_edit:Color, White
Gui, autoregister_edit:Font, S11 CDefault bold, Segoe UI
Gui, autoregister_edit:Add, Text, x12 y9 w450 h20 , Настройки автоматического реестра
Gui, autoregister_edit:Font, S9 CDefault norm, Segoe UI
Gui, autoregister_edit:Add, Button, x12 y369 w210 h30 gAutoregister_Save, Сохранить
Gui, autoregister_edit:Add, Button, x252 y369 w210 h30 gAutoregister_Variables, Переменные

if autoregister_choosed = FBI
	Gui, autoregister_edit:Add, Tab2, x12 y39 w450 h320 , Отыгровка /invite|Отыгровка /uninvite|Отыгровка /giverank|Отыгровка /funinvite|Отыгровка /fgiverank
else
	Gui, autoregister_edit:Add, Tab2, x12 y39 w450 h320 , Отыгровка /invite|Отыгровка /uninvite|Отыгровка /giverank

Gui, autoregister_edit:Tab, Отыгровка /invite
Gui, autoregister_edit:Font, S9 CDefault, Segoe UI

if autoregister_choosed = FBI
{
	Gui, autoregister_edit:Add, Text, x22 y89 w430 h20 , Данные строки будут отправляться в чат с интервалом 1100 мс.
}
else {
	Gui, autoregister_edit:Add, Text, x22 y79 w430 h20 , Данные строки будут отправляться в чат с интервалом 1100 мс.
}

Gui, autoregister_edit:Add, Edit, x22 y109 w430 h230 vautoregister_invite_text, % autoregister_invite_text

Gui, autoregister_edit:Tab, Отыгровка /uninvite
Gui, autoregister_edit:Font, S9 CDefault, Segoe UI

if autoregister_choosed = FBI
{
	Gui, autoregister_edit:Add, Text, x22 y89 w430 h20 , Данные строки будут отправляться в чат с интервалом 1100 мс.
}
else {
	Gui, autoregister_edit:Add, Text, x22 y79 w430 h20 , Данные строки будут отправляться в чат с интервалом 1100 мс.
}

Gui, autoregister_edit:Add, Edit, x22 y109 w430 h230 vautoregister_uninvite_text, % autoregister_uninvite_text

Gui, autoregister_edit:Tab, Отыгровка /giverank
Gui, autoregister_edit:Font, S9 CDefault, Segoe UI

if autoregister_choosed = FBI
{
	Gui, autoregister_edit:Add, Text, x22 y89 w430 h20 , Данные строки будут отправляться в чат с интервалом 1100 мс.
}
else {
	Gui, autoregister_edit:Add, Text, x22 y79 w430 h20 , Данные строки будут отправляться в чат с интервалом 1100 мс.
}

Gui, autoregister_edit:Add, Edit, x22 y109 w430 h230 vautoregister_giverank_text, % autoregister_giverank_text

if autoregister_choosed = FBI
{
	Gui, autoregister_edit:Tab, Отыгровка /funinvite
	Gui, autoregister_edit:Font, S9 CDefault, Segoe UI
	Gui, autoregister_edit:Add, Text, x22 y89 w430 h20 , Данные строки будут отправляться в чат с интервалом 1100 мс.
	Gui, autoregister_edit:Add, Edit, x22 y109 w430 h230 vautoregister_funinvite_text, % autoregister_funinvite_text
	
	Gui, autoregister_edit:Tab, Отыгровка /fgiverank
	Gui, autoregister_edit:Font, S9 CDefault, Segoe UI
	Gui, autoregister_edit:Add, Text, x22 y89 w430 h20 , Данные строки будут отправляться в чат с интервалом 1100 мс.
	Gui, autoregister_edit:Add, Edit, x22 y109 w430 h230 vautoregister_fgiverank_text, % autoregister_fgiverank_text
}

Gui, autoregister_edit:Show, w479 h421, % title

settimer, autoregister_editloop, 1

autoregister_editloop:
IfWinNotExist, ahk_id %autoregister_editwid%
{
	settimer, autoregister_editloop, off
	return
}

IfWinNotActive, ahk_id %autoregister_editwid%
	return

if GetKeyState("Escape", "P")
{
	gui, autoregister_edit:destroy
	KeyWait, Escape, U
}
return

autoregister_editGuiClose:
gui, autoregister_edit:destroy
return

Autoregister_Variables:
Gui, autoregister_edit:+owndialogs
MsgBox, 64, % title,
(
Список переменных:
$name - имя игрока (с которым мы взаимодействуем).
$family - фамилия игрока (с которым мы взаимодействуем).
$id - идентефикатор игрока (с которым мы взаимодействуем).
$action - динамическая переменная, которую вводит пользователь.
$myname - ваше имя на русском (которое вы вводили при первом запуске программы).
$myfamily - ваша фамилия на русском (которое вы вводили при первом запуске программы).

Напоминание: вы можете поменять информацию о себе`, воспользуясь меню GH (Отыгровки > Заполнить информацию о себе).
)
KeyWait, Escape, U
return

AutoregisterButtonSave:
return

Autoregister_Save:
gui, autoregister_edit:submit
Gui, autoregister_edit:destroy

filedelete, autoregister\%autoregister_choosed%\invite.ini
fileappend, % autoregister_invite_text, autoregister\%autoregister_choosed%\invite.ini

filedelete, autoregister\%autoregister_choosed%\uninvite.ini
fileappend, % autoregister_uninvite_text, autoregister\%autoregister_choosed%\uninvite.ini

filedelete, autoregister\%autoregister_choosed%\giverank.ini
fileappend, % autoregister_giverank_text, autoregister\%autoregister_choosed%\giverank.ini

if autoregister_choosed = FBI
{ ;
	filedelete, autoregister\%autoregister_choosed%\funinvite.ini
	fileappend, % autoregister_funinvite_text, autoregister\%autoregister_choosed%\funinvite.ini
	
	filedelete, autoregister\%autoregister_choosed%\fgiverank.ini
	fileappend, % autoregister_fgiverank_text, autoregister\%autoregister_choosed%\fgiverank.ini
}

gui, autoregister_edit:destroy
MsgBox, 64, % title, Сохранено., 1
return

AutoregisterButtonSaveHotkeys:
gui, autoregister_edit:submit, nohide
IniWrite, % AutoregisterHotkeyInvite, config.ini, autoregister, hotkeyInvite
IniWrite, % AutoregisterHotkeyUninvite, config.ini, autoregister, hotkeyUninvite
IniWrite, % AutoregisterHotkeyGiverank, config.ini, autoregister, hotkeyGiverank
gui, autoregister_edit:destroy
MsgBox, 64, % title, Бинды сохранены. Программа будет перезапущена., 4
reload

autoregister_cancel:
chat.show("%t Операция отменена.")
hotkey, f4, off
cancel_register = 1
settimer, chatlogger, on
return

_cmd_arinvite:
if (!autoregister) {
	chat.show("%t Сначала включите функцию.")
	return
}

RegExMatch(fraction, "(.*) ((.*))", autoregister_choosed_name)
autoregister_choosed_name := autoregister_choosed_name1

chat.show("%t Для отмены нажмите 'F4'. Текущая отыгровка: " autoregister_choosed_name ".")
hotkey, f4, autoregister_cancel
hotkey, f4, on

if (!sortscreenstate)
	chat.show("%t Рекомендуется включить функцию '%bПомощник в отчетах > Сортировка скриншотов%w' и GH сам переместит скриншоты.")

cancel_register = 0
settimer, chatlogger, off
autoregister_id := chat.input("Введите ID игрока, которого нужно внести в реестр.")
if (autoregister_id < 0) or (autoregister_id = "") {
	settimer, chatlogger, on
	return
}

if cancel_register = 1
{
	cancel_register = 0
	settimer, chatlogger, on
	return
}

autoregister_id := Round(autoregister_id)

sleep 500
autoregister_reason := chat.input("Укажите причину, по которой нужно внести игрока в реестр.")
if (!autoregister_reason) {
	settimer, chatlogger, on
	return
}

if cancel_register = 1
{
	cancel_register = 0
	settimer, chatlogger, on
	return
}

sleep 500
chat.send("/id " autoregister_id)
sleep 2000

index = 0
loop {
	haystack := GetChatLine(index)
	RegExMatch(haystack, "Игрок (.*)\_(.*)\[(.*)\]", pname)
	
	autoregister_name := pname1
	autoregister_family := pname2
	index++
	
	if autoregister_name
		break
	
	if index > 9
	{
		chat.show("%t Не найдена информация об игроке. Операция отменена.")
		chat.show("%t Проверьте, может какие-нибудь программы не дают доступ к чатлогу.")
		settimer, chatlogger, on
		return
	}
}

if cancel_register = 1
{
	cancel_register = 0
	settimer, chatlogger, on
	return
}

_retryAR_Setrank:
sleep 500
autoregister_setrank := chat.input("Укажите на какой ранг принять игрока (номер ранга).")
if (!autoregister_setrank)
	return

if autoregister_setrank is not integer
{
	chat.show("%t Нужно указать целое число!")
	goto _retryAR_Setrank
}

bl_finded := blacklist[Trim(chat_public_nick)]
if (bl_finded)  {
	Loop, parse, bl_finded, `,
	{
		if A_Index = 1
			bl_finded_date := A_LoopField
	
		if A_Index = 2
			bl_finded_server := A_LoopField
	}
	
	loop, parse, bl_finded_was, `,
	{
		if chat_public_nick = %A_LoopField%
		{
			settimer, chatlogger, on
			return
		}
	}
	
	bl_finded_was = %bl_finded_was%,%chat_public_nick%
	chat.show("%t " chat_public_nick " находится в ОЧС на " bl_finded_server " сервере: " bl_finded_date ".")
}

ar_state = 0
approximate_expectation = 0
Loop, read, autoregister\%autoregister_choosed%\invite.ini
{
	ar_state = 1
	
	if cancel_register = 1
	{
		cancel_register = 0
		settimer, chatlogger, on
		return
	}

	register_field = %A_LoopReadLine%
	StringReplace, register_field, register_field, % "$name", % autoregister_name, All
	StringReplace, register_field, register_field, % "$family", % autoregister_family, All
	StringReplace, register_field, register_field, % "$id", % autoregister_id, All
	StringReplace, register_field, register_field, % "$action", % autoregister_reason, All
	StringReplace, register_field, register_field, % "$myname", % rus_name, All
	StringReplace, register_field, register_field, % "$myfamily", % rus_family, All
	
	chat.send(register_field)
	approximate_expectation+=1300
}

sleep %approximate_expectation%
sleep 3000

if ar_state = 0
{
	chat.show("{4169E1}[GOS Helper] Отыгровка не найдена.")
	settimer, chatlogger, on
	return
}

if cancel_register = 1
{
	cancel_register = 0
	settimer, chatlogger, on
	return
}

sleep 5100

chat.send("/time", 1)
sleep 1000
ControlSend,, {F8 down}, ahk_exe gta_sa.exe
sleep 250
ControlSend,, {F8 up}, ahk_exe gta_sa.exe

if autoregister_setrank > 1
{
	approximate_expectation = 0
	chat.show("%t Теперь повышаем...")
	sleep 1300
	
	loop, % autoregister_setrank-1
	{
		chat.send("/giverank " autoregister_id " +")
		approximate_expectation+=1400
	}
	
	sleep %approximate_expectation%
	if arsavescreens
	{
		sleep 1000
		chat.send("/time", 1)
		sleep 1000
		ControlSend,, {F8}, ahk_exe gta_sa.exe
	}
}

if cancel_register = 1
{
	cancel_register = 0
	settimer, chatlogger, on
	return
}

Loop, parse, AutoregisterRankList%autoregister_choosed%, `,
{
	if autoregister_setrank > 1
	{
		if (autoregister_setrank != A_Index) {
			continue
		}
		else {
			autoregister_rank_next := A_LoopField
			break
		}
	}
	
	autoregister_rank_next := A_LoopField
	break
}

settimer, chatlogger, on

zanes = 0
IniRead, AutoregisterFormatText, config.ini, Autoregister, formatText
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $action, % "Принят", All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $name, % autoregister_name, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $mynick, % playername, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $family, % autoregister_family, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $rank1, Гражданский, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $rank2, % autoregister_rank_next, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $drank, % autoregister_rank_next, All ; different rank
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $reason, % autoregister_reason, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $imgur, % uploadScreenToImgur(), All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $hour, % A_Hour, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $min, % A_Min, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $sec, % A_Hour, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $day, % A_DD, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $year, % str.right(A_YYYY, 2), All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $month, % A_MM, All

IniWrite, % AutoregisterFormatText, autoregister\register.txt, % A_DD "." A_MM "." str.right(A_YYYY, 2)
chat.show("%t Занесение {4169E1}" autoregister_name "_" autoregister_family "[" autoregister_id "] {FFFFFF}успешно.")
hotkey, F4, off

if sortscreenstate
	sortscreen_to = Инвайты|%autoregister_name%_%autoregister_family%

zanes = 1
settimer, chatlogger, on
return

_cmd_aruninvite:
if (!autoregister) {
	chat.show("%t Сначала включите функцию.")
	return
}

RegExMatch(fraction, "(.*) ((.*))", autoregister_choosed_name)
autoregister_choosed_name := autoregister_choosed_name1

chat.show("%t Для отмены нажмите 'F4'. Текущая отыгровка: " autoregister_choosed_name ".")
hotkey, f4, autoregister_cancel
hotkey, f4, on
cancel_register = 0

if (!sortscreenstate)
	chat.show("%t Рекомендуется включить функцию '%bПомощник в отчетах > Сортировка скриншотов%w' и GH сам переместит скриншоты.")

settimer, chatlogger, off
autoregister_id := chat.input("Введите ID игрока, которого нужно внести в реестр.")
if (autoregister_id < 0) or (autoregister_id = "") {
	settimer, chatlogger, on
	return
}

if cancel_register = 1
{
	cancel_register = 0
	settimer, chatlogger, on
	return
}

autoregister_id := Round(autoregister_id)
sleep 500

if cancel_register = 1
{
	cancel_register = 0
	settimer, chatlogger, on
	return
}

autoregister_reason := chat.input("Укажите причину, по которой нужно внести игрока в реестр.")
if (!autoregister_reason) {
	settimer, chatlogger, on
	return
}

sleep 500

if cancel_register = 1
{
	cancel_register = 0
	settimer, chatlogger, on
	return
}

autoregister_rank_moment := chat.input("Укажите ранг игрока на данный момент (именно номер ранга, а не его название), которого нужно внести в реестр.")
if (!autoregister_rank_moment) {
	settimer, chatlogger, on
	return
}

autoregister_rank_moment := Round(autoregister_rank_moment)

loop, parse, AutoregisterRankList%autoregister_choosed%, `,
{
	if A_Index = %autoregister_rank_moment%
	{
		autoregister_rank_name := A_LoopField
		break
	}
}

sleep 500

if cancel_register = 1
{
	cancel_register = 0
	settimer, chatlogger, on
	return
}

chat.send("/id " autoregister_id)
sleep 2000

index = 0
loop {
	haystack := GetChatLine(index)
	RegExMatch(haystack, "Игрок (.*)\_(.*)\[(.*)\]", pname)
	
	autoregister_name := pname1
	autoregister_family := pname2
	index++
	
	if autoregister_name
		break
	
	if index > 9
	{
		chat.show("%t Не найдена информация об игроке. Операция отменена.")
		chat.show("%t Проверьте, может какие-нибудь программы не дают доступ к чатлогу.")
		settimer, chatlogger, on
		return
	}
}

ar_state = 0
approximate_expectation = 0
Loop, read, autoregister\%autoregister_choosed%\uninvite.ini
{
	ar_state = 1
	if cancel_register = 1
	{
		cancel_register = 0
		return
	}

	register_field = %A_LoopReadLine%
	StringReplace, register_field, register_field, % "$name", % autoregister_name, All
	StringReplace, register_field, register_field, % "$family", % autoregister_family, All
	StringReplace, register_field, register_field, % "$id", % autoregister_id, All
	StringReplace, register_field, register_field, % "$action", % autoregister_reason, All
	StringReplace, register_field, register_field, % "$myname", % rus_name, All
	StringReplace, register_field, register_field, % "$myfamily", % rus_family, All
	
	chat.send(register_field)
	approximate_expectation+=1200
}

sleep %approximate_expectation%

if ar_state = 0
{
	chat.show("{4169E1}[GOS Helper] Отыгровка не найдена.")
	settimer, chatlogger, on
	return
}

if arsavescreens
{
	sleep 1000
	chat.send("/time", 1)
	sleep 1000
	ControlSend,, {F8}, ahk_exe gta_sa.exe
}

zanes = 0
IniRead, AutoregisterFormatText, config.ini, Autoregister, formatText
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $action, % "Уволен", All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $name, % autoregister_name, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $mynick, % playername, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $family, % autoregister_family, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $rank1, % autoregister_rank_name, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $rank2, Гражданский, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $drank, % autoregister_rank_name, All ; different rank
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $reason, % autoregister_reason, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $imgur, % uploadScreenToImgur(), All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $hour, % A_Hour, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $min, % A_Min, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $sec, % A_Hour, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $day, % A_DD, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $year, % str.right(A_YYYY, 2), All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $month, % A_MM, All

IniWrite, % AutoregisterFormatText, autoregister\register.txt, % A_DD "." A_MM "." str.right(A_YYYY, 2)
chat.show("%t Занесение {4169E1}" autoregister_name "_" autoregister_family "[" autoregister_id "] {FFFFFF}успешно.")
hotkey, F4, off

if sortscreenstate
	sortscreen_to = Увольнения|%autoregister_name%_%autoregister_family%

zanes = 1
settimer, chatlogger, on
return

_cmd_arfrank:
if (!autoregister) {
	chat.show("%t Сначала включите функцию.")
	return
}

if (autoregister_choosed != "FBI") {
	chat.show("%t Недоступно в выбранной фракции.")
	return
}

RegExMatch(fraction, "(.*) ((.*))", autoregister_choosed_name)
autoregister_choosed_name := autoregister_choosed_name1

chat.show("%t Для отмены нажмите 'F4'. Текущая отыгровка: " autoregister_choosed_name ".")
hotkey, f4, autoregister_cancel
hotkey, f4, on

cancel_register = 0
if (!sortscreenstate)
	chat.show("%t Рекомендуется включить функцию '%bПомощник в отчетах > Сортировка скриншотов%w' и GH сам переместит скриншоты.")

autoregister_id := chat.input("Введите ID игрока, которого нужно внести в реестр.")
if (autoregister_id < 0) or (autoregister_id = "") {
	settimer, chatlogger, on
	return
}

if cancel_register = 1
{
	cancel_register = 0
	settimer, chatlogger, on
	return
}

autoregister_id := Round(autoregister_id)
sleep 500

autoregister_reason := chat.input("Укажите причину, по которой нужно внести игрока в реестр.")
if (autoregister_reason = -1) {
	settimer, chatlogger, on
	return
}

sleep 500

if cancel_register = 1
{
	cancel_register = 0
	settimer, chatlogger, on
	return
}

settimer, chatlogger, off
sleep 500
chat.send("/id " autoregister_id)
sleep 2000

if cancel_register = 1
{
	cancel_register = 0
	settimer, chatlogger, on
	return
}

index = 0
loop {
	haystack := GetChatLine(index)
	RegExMatch(haystack, "Игрок (.*)\_(.*)\[(.*)\]", pname)
	
	autoregister_name := pname1
	autoregister_family := pname2
	index++
	
	if autoregister_name
		break
	
	if index > 9
	{
		chat.show("%t Не найдена информация об игроке. Операция отменена.")
		chat.show("%t Проверьте, может какие-нибудь программы не дают доступ к чатлогу.")
		settimer, chatlogger, on
		return
	}
}

sleep 500
if cancel_register = 1
{
	cancel_register = 0
	settimer, chatlogger, on
	return
}

ar_state = 0
approximate_expectation = 0
Loop, read, autoregister\%autoregister_choosed%\fgiverank.ini
{
	ar_state = 1
	if cancel_register = 1
	{
		cancel_register = 0
		settimer, chatlogger, on
		return
	}

	register_field = %A_LoopReadLine%
	StringReplace, register_field, register_field, % "$name", % autoregister_name, All
	StringReplace, register_field, register_field, % "$family", % autoregister_family, All
	StringReplace, register_field, register_field, % "$id", % autoregister_id, All
	StringReplace, register_field, register_field, % "$action", % autoregister_rank_action, All
	StringReplace, register_field, register_field, % "$myname", % rus_name, All
	StringReplace, register_field, register_field, % "$myfamily", % rus_family, All
	
	chat.send(register_field)
	approximate_expectation+=1200
}

sleep %approximate_expectation%
if ar_state = 0
{
	chat.show("{4169E1}[GOS Helper] Отыгровка не найдена.")
	settimer, chatlogger, on
	return
}

if arsavescreens
{
	sleep 1000
	chat.send("/time", 1)
	sleep 1000
	ControlSend,, {F8}, ahk_exe gta_sa.exe
}

autoregister_rank_prev := Trim(chat.input("Укажите ранг человека до понижения, который должен быть внесен в реестр."))
if (autoregister_rank_prev = "") {
	settimer, chatlogger, on
	return
}

autoregister_rank_moment := Trim(chat.input("Укажите ранг человека после понижения, который должен быть внесен в реестр."))
if (autoregister_rank_moment = "") {
	settimer, chatlogger, on
	return
}

zanes = 0
IniRead, AutoregisterFormatText, config.ini, Autoregister, formatText
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $action, % "Понижен", All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $name, % autoregister_name, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $mynick, % playername, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $family, % autoregister_family, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $rank1, % autoregister_rank_prev, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $rank2, % autoregister_rank_moment, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $drank, % autoregister_rank_moment, All ; different rank
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $reason, % autoregister_reason, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $imgur, % uploadScreenToImgur(), All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $hour, % A_Hour, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $min, % A_Min, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $sec, % A_Hour, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $day, % A_DD, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $year, % str.right(A_YYYY, 2), All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $month, % A_MM, All

IniWrite, % AutoregisterFormatText, autoregister\register.txt, % A_DD "." A_MM "." str.right(A_YYYY, 2)
chat.show("%t Занесение {4169E1}" autoregister_name "_" autoregister_family "[" autoregister_id "] {FFFFFF}успешно.")
hotkey, F4, off

if sortscreenstate
	sortscreen_to = Ф-ранг|%autoregister_name%_%autoregister_family%

zanes = 1
settimer, chatlogger, on
return

_cmd_arfuninvite:
if (!autoregister) {
	chat.show("%t Сначала включите функцию.")
	return
}

if (autoregister_choosed != "FBI") {
	chat.show("%t Недоступно в выбранной фракции.")
	return
}

RegExMatch(fraction, "(.*) ((.*))", autoregister_choosed_name)
autoregister_choosed_name := autoregister_choosed_name1

chat.show("%t Для отмены нажмите 'F4'. Текущая отыгровка: " autoregister_choosed_name ".")
hotkey, f4, autoregister_cancel
hotkey, f4, on

if (!sortscreenstate)
	chat.show("%t Рекомендуется включить функцию '%bПомощник в отчетах > Сортировка скриншотов%w' и GH сам переместит скриншоты.")

cancel_register = 0

autoregister_id := chat.input("Введите ID игрока, которого нужно внести в реестр.")
if (autoregister_id < 0) or (autoregister_id = "") {
	settimer, chatlogger, on
	return
}

if cancel_register = 1
{
	cancel_register = 0
	settimer, chatlogger, on
	return
}

autoregister_id := Round(autoregister_id)
sleep 500

autoregister_reason := chat.input("Укажите причину, по которой нужно внести игрока в реестр.")
if (autoregister_reason = -1) {
	settimer, chatlogger, on
	return
}

sleep 500

if cancel_register = 1
{
	cancel_register = 0
	settimer, chatlogger, on
	return
}

settimer, chatlogger, off
sleep 500
chat.send("/id " autoregister_id)
sleep 2000

if cancel_register = 1
{
	cancel_register = 0
	settimer, chatlogger, on
	return
}

index = 0
loop {
	haystack := GetChatLine(index)
	RegExMatch(haystack, "Игрок (.*)\_(.*)\[(.*)\]", pname)
	
	autoregister_name := pname1
	autoregister_family := pname2
	index++
	
	if autoregister_name
		break
	
	if index > 9
	{
		chat.show("%t Не найдена информация об игроке. Операция отменена.")
		chat.show("%t Проверьте, может какие-нибудь программы не дают доступ к чатлогу.")
		settimer, chatlogger, on
		return
	}
}

sleep 500
if cancel_register = 1
{
	cancel_register = 0
	settimer, chatlogger, on
	return
}

ar_state = 0
approximate_expectation = 0
Loop, read, autoregister\%autoregister_choosed%\funinvite.ini
{
	ar_state = 1
	if cancel_register = 1
	{
		cancel_register = 0
		settimer, chatlogger, on
		return
	}

	register_field = %A_LoopReadLine%
	StringReplace, register_field, register_field, % "$name", % autoregister_name, All
	StringReplace, register_field, register_field, % "$family", % autoregister_family, All
	StringReplace, register_field, register_field, % "$id", % autoregister_id, All
	StringReplace, register_field, register_field, % "$action", % autoregister_rank_action, All
	StringReplace, register_field, register_field, % "$myname", % rus_name, All
	StringReplace, register_field, register_field, % "$myfamily", % rus_family, All
	
	chat.send(register_field)
	approximate_expectation+=1200
}

sleep %approximate_expectation%
if ar_state = 0
{
	chat.show("{4169E1}[GOS Helper] Отыгровка не найдена.")
	settimer, chatlogger, on
	return
}

if arsavescreens
{
	sleep 1000
	chat.send("/time", 1)
	sleep 1000
	ControlSend,, {F8}, ahk_exe gta_sa.exe
}

autoregister_rank_prev := Trim(chat.input("Укажите ранг человека до увольнения, который должен быть внесен в реестр."))
if (autoregister_rank_prev = "") {
	settimer, chatlogger, on
	return
}

autoregister_rank_moment = Гражданский
zanes = 0
IniRead, AutoregisterFormatText, config.ini, Autoregister, formatText
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $action, % "Уволен", All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $name, % autoregister_name, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $mynick, % playername, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $family, % autoregister_family, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $rank1, % autoregister_rank_prev, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $rank2, % autoregister_rank_moment, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $drank, % autoregister_rank_prev, All ; different rank
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $reason, % autoregister_reason, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $imgur, % uploadScreenToImgur(), All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $hour, % A_Hour, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $min, % A_Min, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $sec, % A_Hour, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $day, % A_DD, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $year, % str.right(A_YYYY, 2), All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $month, % A_MM, All

IniWrite, % AutoregisterFormatText, autoregister\register.txt, % A_DD "." A_MM "." str.right(A_YYYY, 2)
chat.show("%t Занесение {4169E1}" autoregister_name "_" autoregister_family "[" autoregister_id "] {FFFFFF}успешно.")
hotkey, F4, off

if sortscreenstate
	sortscreen_to = Ф-увольнения|%autoregister_name%_%autoregister_family%

zanes = 1
settimer, chatlogger, on
return

_cmd_arrank:
if (!autoregister) {
	chat.show("%t Сначала включите функцию.")
	return
}

RegExMatch(fraction, "(.*) ((.*))", autoregister_choosed_name)
autoregister_choosed_name := autoregister_choosed_name1

chat.show("%t Для отмены нажмите 'F4'. Текущая отыгровка: " autoregister_choosed_name ".")
hotkey, f4, autoregister_cancel
hotkey, f4, on

if (!sortscreenstate)
	chat.show("%t Рекомендуется включить функцию '%bПомощник в отчетах > Сортировка скриншотов%w' и GH сам переместит скриншоты.")

cancel_register = 0

autoregister_id := chat.input("Введите ID игрока, которого нужно внести в реестр.")
if (autoregister_id < 0) or (autoregister_id = "") {
	settimer, chatlogger, on
	return
}

if cancel_register = 1
{
	cancel_register = 0
	settimer, chatlogger, on
	return
}

autoregister_id := Round(autoregister_id)
sleep 500

autoregister_reason := chat.input("Укажите причину, по которой нужно внести игрока в реестр.")
if (autoregister_reason = -1) {
	settimer, chatlogger, on
	return
}

sleep 500

if cancel_register = 1
{
	cancel_register = 0
	settimer, chatlogger, on
	return
}

autoregister_rank := chat.input("Укажите ранг игрока на данный момент (именно номер ранга, а не его название), которого нужно внести в реестр.")
if (!autoregister_rank) {
	settimer, chatlogger, on
	return
}

autoregister_rank := Round(autoregister_rank)

sleep 500

if cancel_register = 1
{
	cancel_register = 0
	settimer, chatlogger, on
	return
}

autoregister_rank_action := chat.input("Для повышения игрока напишите 1, для понижения 0.")
if (autoregister_rank_action = -1) {
	settimer, chatlogger, on
	return
}

if autoregister_rank_action = 0
	goto _autoregister_rank_action

if autoregister_rank_action = 1
	goto _autoregister_rank_action

if cancel_register = 1
{
	cancel_register = 0
	settimer, chatlogger, on
	return
}

chat.show("%t Вы не указали '0' или '1' для взаимодействия с рангом.")
hotkey, F4, off
settimer, chatlogger, on
return

_autoregister_rank_action:
settimer, chatlogger, off
sleep 500
chat.send("/id " autoregister_id)
sleep 2000

if cancel_register = 1
{
	cancel_register = 0
	settimer, chatlogger, on
	return
}

Loop, parse, AutoregisterRankList%autoregister_choosed%, `,
{
	if autoregister_rank_action = 0
	{
		if A_Index = %autoregister_rank%
		{
			autoregister_rank_moment := A_LoopField
			break
		}
		
		if A_Index < %autoregister_rank%
			autoregister_rank_next := A_LoopField
	}

	if autoregister_rank_action = 1
	{
		if A_Index = %autoregister_rank%
			autoregister_rank_moment := A_LoopField
	
		if A_Index > %autoregister_rank%
		{
			autoregister_rank_next := A_LoopField
			break
		}
	}
}

if autoregister_rank_action = 1
	autoregister_rank_action := "+"
else
	autoregister_rank_action := "-"

index = 0
loop {
	haystack := GetChatLine(index)
	RegExMatch(haystack, "Игрок (.*)\_(.*)\[(.*)\]", pname)
	
	autoregister_name := pname1
	autoregister_family := pname2
	index++
	
	if autoregister_name
		break
	
	if index > 9
	{
		chat.show("%t Не найдена информация об игроке. Операция отменена.")
		chat.show("%t Проверьте, может какие-нибудь программы не дают доступ к чатлогу.")
		settimer, chatlogger, on
		return
	}
}

sleep 500
if cancel_register = 1
{
	cancel_register = 0
	settimer, chatlogger, on
	return
}

ar_state = 0
approximate_expectation = 0
Loop, read, autoregister\%autoregister_choosed%\giverank.ini
{
	ar_state = 1
	if cancel_register = 1
	{
		cancel_register = 0
		settimer, chatlogger, on
		return
	}

	register_field = %A_LoopReadLine%
	StringReplace, register_field, register_field, % "$name", % autoregister_name, All
	StringReplace, register_field, register_field, % "$family", % autoregister_family, All
	StringReplace, register_field, register_field, % "$id", % autoregister_id, All
	StringReplace, register_field, register_field, % "$action", % autoregister_rank_action, All
	StringReplace, register_field, register_field, % "$myname", % rus_name, All
	StringReplace, register_field, register_field, % "$myfamily", % rus_family, All
	
	chat.send(register_field)
	approximate_expectation+=1200
}

sleep %approximate_expectation%

if ar_state = 0
{
	chat.show("{4169E1}[GOS Helper] Отыгровка не найдена.")
	settimer, chatlogger, on
	return
}

if arsavescreens
{
	sleep 1000
	chat.send("/time", 1)
	sleep 1000
	ControlSend,, {F8}, ahk_exe gta_sa.exe
}

zanes = 0
IniRead, AutoregisterFormatText, config.ini, Autoregister, formatText
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $name, % autoregister_name, All

if (autoregister_rank_action = "-")
	StringReplace, AutoregisterFormatText, AutoregisterFormatText, $action, % "Понижен", All
else
	StringReplace, AutoregisterFormatText, AutoregisterFormatText, $action, % "Повышен", All

StringReplace, AutoregisterFormatText, AutoregisterFormatText, $mynick, % playername, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $family, % autoregister_family, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $rank1, % autoregister_rank_moment, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $rank2, % autoregister_rank_next, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $drank, % autoregister_rank_next, All ; different rank
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $reason, % autoregister_reason, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $imgur, % uploadScreenToImgur(), All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $hour, % A_Hour, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $min, % A_Min, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $sec, % A_Hour, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $day, % A_DD, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $year, % str.right(A_YYYY, 2), All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $month, % A_MM, All

IniWrite, % AutoregisterFormatText, autoregister\register.txt, % A_DD "." A_MM "." str.right(A_YYYY, 2)
chat.show("%t Занесение {4169E1}" autoregister_name "_" autoregister_family "[" autoregister_id "] {FFFFFF}успешно.")
hotkey, F4, off

if sortscreenstate
	sortscreen_to = Ранг|%autoregister_name%_%autoregister_family%

zanes = 1
settimer, chatlogger, on
return

StopVoice:
Hotkey, End, off
SoundPlay, nul
return

mode_f8hk:
chat.send("/time", 1)
sleep 1000
ControlSend,, {F8 down}, ahk_exe gta_sa.exe
sleep 100
ControlSend,, {F8 up}, ahk_exe gta_sa.exe
return

_generateVK_Menu:
Menu, vk_menu, DeleteAll
Menu, vk_menu, add, Записанные виртуальные идентификаторы, virt_ids
Menu, vk_menu, Add, Выйти из аккаунта %first_name% %last_name%, exitSession
Menu, vk_menu, Disable, Записанные виртуальные идентификаторы
Menu, vk_menu, add, 
Menu, vk_menu, add, Сохранять виртуальные идентификаторы, vkmsg_rememberVirtIds
Menu, vk_menu, add, Автоматически прочитывать полученное сообщение, vkmsg_autoread
Menu, vk_menu, add, Автоматически прослушивать голосовые сообщения, vkmsg_autoplayVoice
return

virt_ids:
Gui, +OwnDialogs
MsgBox, 64, % title, GOS Helper сохраняет базу данных виртуальных идентификаторов VKMSG в файл. Ничего не трогайте`, если Вы не разбираетесь в этом.
Run, virt_ids.ini,, UseErrorLevel
if errorlevel
	MsgBox, 64, % title, По всей видимости база данных еще не записана.

return

openfolder:
Run, %A_ProgramFiles%\GOS Helper,, UseErrorLevel
if errorlevel
{
	MsgBox, 64, % title, Папка не открылась. Попробуйте перейти в папку самостоятельно`, ориентируясь на путь: %A_ProgramFiles%\GOS Helper.
}
return

reload:
reload

devloop:
settimer, devloop, off
return

reportHelpPost:
if !ReportHelpPostNeedStay
	ReportHelpPostNeedStay = 0

if !ReportHelpPostName
	ReportHelpPostName = КПП

if !ReportHelpPostNeedTime
	ReportHelpPostNeedTime = 60

if !ReportHelpPostInterval
	ReportHelpPostInterval =  10

Gui, reportHelpPost:Destroy
Gui, reportHelpPost:-MinimizeBox +hwndReportHelpPostWID
Gui, reportHelpPost:Color, White
Gui, reportHelpPost:Font, S30 CDefault, Segoe UI
Gui, reportHelpPost:Add, Text, x22 y29 w430 h50 +Center vReportHelpPostNeedStay, % ReportHelpPostNeedStay
Gui, reportHelpPost:Font, S10 CDefault, Segoe UI
Gui, reportHelpPost:Add, Text, x22 y84 w430 h20 +Center, минут осталось отстоять посту
Gui, reportHelpPost:Font, S9 CDefault, Segoe UI
Gui, reportHelpPost:Add, GroupBox, x17 y119 w440 h10 +Center, 
Gui, reportHelpPost:Font, S9 CDefault, Segoe UI
Gui, reportHelpPost:Add, Text, x22 y139 w310 h20 , Укажите название поста:
Gui, reportHelpPost:Add, Edit, x342 y139 w110 h20 vReportHelpPostName, % ReportHelpPostName
Gui, reportHelpPost:Add, Text, x22 y169 w310 h20 , Сколько времени (минут) нужно пробыть на посту?
Gui, reportHelpPost:Add, Edit, x342 y169 w110 h20 number vReportHelpPostNeedTime, % ReportHelpPostNeedTime
Gui, reportHelpPost:Add, Text, x22 y199 w310 h30 , Интервал времени (минут)`, через которое будет делаться доклад и скриншот:
Gui, reportHelpPost:Add, Edit, x342 y204 w110 h20 number vReportHelpPostInterval, % ReportHelpPostInterval
Gui, reportHelpPost:Font, S9 CDefault, Consolas
Gui, reportHelpPost:Add, Text, x22 y239 w430 h50 +Center vReportHelpPostPreview, `nТут появится предварительный текст доклада.
Gui, reportHelpPost:Font, S9 CDefault Norm, Segoe UI
Gui, reportHelpPost:Add, Button, x187 y299 w100 h30 gSaveReportHelpPost vSaveReportHelpPost, Сохранить
Gui, reportHelpPost:Show, w479 h345, % title

settimer, reportHelpPostloop, 1

reportHelpPostLoop:
IfWinNotExist, ahk_id %ReportHelpPostWID%
{
	settimer, reportHelpPostLoop, off
	return
}

IfWinNotActive, ahk_id %ReportHelpPostWID%
	return

if GetKeyState("Escape", "P") {
	Gui, reportHelpPost:destroy
	KeyWait, Escape, U
}

ToolTip
return

SaveReportHelpPost:
Gui, reportHelpPost:+OwnDialogs
if ReportHelpPost_Started = 1
{
	MsgBox, 49, % title, Внимание! Вы уже стоите на посту! Если Вы нажмете 'OK'`, то счетчик сбросится и стоять пост придется ЗАНОВО!
	IfMsgBox, Cancel
		return
}

Gui, reportHelpPost:+OwnDialogs
GuiControl, reportHelpPost:disable, SaveReportHelpPost
Gui, reportHelpPost:submit, nohide
if !ReportHelpPostName
{
	MsgBox, 16, % title, Пожалуйста`, укажите название поста.
	GuiControl, reportHelpPost:enable, SaveReportHelpPost
	return
}

if !ReportHelpPostNeedTime
{
	MsgBox, 16, % title, Пожалуйста`, укажите время`, которое нужно пробыть на посту.
	GuiControl, reportHelpPost:enable, SaveReportHelpPost
	return
}

if !ReportHelpPostInterval
{
	MsgBox, 16, % title, Пожалуйста`, укажите интервал времени`, через которое будет делаться доклад и скриншот.
	GuiControl, reportHelpPost:enable, SaveReportHelpPost
	return
}

GuiControl, reportHelpPost:-Center, ReportHelpPostPreview
if !tag
	GuiControl, reportHelpPost:, ReportHelpPostPreview, [%A_Hour%:%A_Min%:%A_Sec%] [R] %rang% %playername%[84]: Докладывает: %rus_name% %rus_family% | Пост: %ReportHelpPostName% | Состояние: Стабильное.
else
	GuiControl, reportHelpPost:, ReportHelpPostPreview, [%A_Hour%:%A_Min%:%A_Sec%] [R] %rang% %playername%[84]: [%tag%] Докладывает: %rus_name% %rus_family% | Пост: %ReportHelpPostName% | Состояние: Стабильное.

ReportHelpPostNeedStay := ReportHelpPostNeedTime
GuiControl, reportHelpPost:, ReportHelpPostNeedStay, % ReportHelpPostNeedTime
GuiControl, reportHelpPost:+ReadOnly, ReportHelpPostName
GuiControl, reportHelpPost:+ReadOnly, ReportHelpPostNeedTime
GuiControl, reportHelpPost:+ReadOnly, ReportHelpPostInterval

MsgBox, 64, % title, Информация сохранена. Предварительный просмотр доклада обновлен (если текст не вместился`, то значит Ваш ник слишком длинный). Теперь откройте игру и нажмите на F12`, с этого момента помощник поможет отстоять пост. Для отмены поста используйте команду '/cancelpost'.

hotkey, F12, ReportHelpPost_Start
hotkey, F12, On
return

_cmd_cancelpost:
if ReportHelpPost_Started = 1
{
	chat.show("%t Вы еще не начали стоять на посту.")
	return
}

chat.show("%t Пост отменен.")
_cancelpost:
hotkey, F12, off
settimer, reportHelpPost_Warning, off
settimer, reportHelpPost_MinuteMinus, off
settimer, reportHelpPost_Doklad, off

ReportHelpPost_Started = 0
return

ReportHelpPost_Start:
gui, reportHelpPost:destroy
ReportHelpPost_Started = 1

chat.show("%t Помощник на посту начал работу. Не ставьте игру на паузу (Escape), сворачивать можно.")
sleep 2500
gosub reportHelpPost_Doklad

settimer, reportHelpPost_Warning, % (ReportHelpPostInterval*60000)-60000
settimer, reportHelpPost_MinuteMinus, 60000
settimer, reportHelpPost_Doklad, % ReportHelpPostInterval*60000
return

reportHelpPost_MinuteMinus:
ReportHelpPostNeedStay-=1

IfWinExist, ahk_id %ReportHelpPostWID%
	GuiControl, ReportHelpPost:, ReportHelpPostNeedStay, % ReportHelpPostNeedStay

return

reportHelpPost_Warning:
settimer, reportHelpPost_Warning, off
IfWinNotActive, ahk_exe gta_sa.exe
{
	TrayTip, % title, У вас пост через минуту!
	SoundBeep, 100, 500
}
else {
	chat.show("%t У вас пост через минуту! Если Вы не на посту, то скорее двигайтесь к нему!")
	SoundBeep, 100, 500
}
return

reportHelpPost_Doklad:
IfWinNotActive, ahk_exe gta_sa.exe
	WinActivate, ahk_exe gta_sa.exe

if tag
	chat.send("/r [" tag "] Докладывает: " rus_name " " rus_family " | Пост: " ReportHelpPostName " | Состояние: Стабильное.")
else
	chat.send("/r Докладывает: " rus_name " " rus_family " | Пост: " ReportHelpPostName " | Состояние: Стабильное.")

settimer, chatlogger, off
sleep, 3000
chat.send("/time", 1)
sleep 1500
ControlSend,, {F8}, ahk_exe gta_sa.exe
sleep 1500

if sortscreenstate
	sortscreen_to = Пост|%A_Hour%.%A_Min%

settimer, chatlogger, on

if ReportHelpPostNeedStay < 1
{
	chat.show("%t Вы отстояли {4169E1}" ReportHelpPostNeedTime "{FFFFFF} минут(-ы) на посту! Мои поздравления!")
	goto _cancelpost
}

chat.show("%t Следующий доклад будет через " ReportHelpPostInterval " минут(-ы).")

settimer, reportHelpPost_Warning, on
return

autoregister_format:
IniRead, AutoregisterFormatText, config.ini, Autoregister, formatText

Gui, autoregister_format:Destroy
Gui, autoregister_format:-MinimizeBox +hwndautoregister_formatwid
Gui, autoregister_format:Color, White
Gui, autoregister_format:Font, S12 CDefault bold, Segoe UI
Gui, autoregister_format:Add, Text, x12 y9 w450 h20 , Настройка формата записи автоматического реестра
Gui, autoregister_format:Font, S9 CDefault norm, Segoe UI
Gui, autoregister_format:Add, Text, x12 y39 w450 h110 gVarARFormatList, Используйте переменные`, без них никуда в настройке формата. Нажмите на этот текст чтобы открыть список переменных.
Gui, autoregister_format:Add, GroupBox, x12 w450 h10 , 
Gui, autoregister_format:Add, Edit, x12 w450 h20 vAutoregisterFormatText, % AutoregisterFormatText
Gui, autoregister_format:Font, S9 CDefault, Consolas
Gui, autoregister_format:Add, Text, x12 w450 h40 vAutoregisterFormatPreview, Предварительный просмотр будет доступен после сохранения настроек.
Gui, autoregister_format:Font, S9 CDefault, Segoe UI
Gui, autoregister_format:Add, Button, x187 w100 h30 gAutoregisterFormatSave vAutoregisterFormatSave, Сохранить
Gui, autoregister_format:Show, w479, % title

settimer, autoregister_formatloop, 1

autoregister_formatloop:
IfWinNotExist, ahk_id %autoregister_formatwid%
{
	SetTimer, autoregister_formatloop, off
	return
}

IfWinNotActive, ahk_id %autoregister_formatwid%
	return

if GetKeyState("Escape", "P") {
	gui, autoregister_format:destroy
	KeyWait, Escape, U
}
return

AutoregisterFormatSave:
Gui, autoregister_format:submit, nohide
Gui, autoregister_format:+OwnDialogs

GuiControl, autoregister_format:disable, AutoregisterFormatSave

if !AutoregisterFormatText
{
	MsgBox, 16, % title, Сначала укажите формат.
	GuiControl, autoregister_format:enable, AutoregisterFormatSave
	return
}

IniWrite, % AutoregisterFormatText, config.ini, Autoregister, formatText
if AutoregisterFormatText not contains `$imgur
	Control, Uncheck,, Button2, ahk_id %autoregisterwid%

StringReplace, AutoregisterFormatText, AutoregisterFormatText, $mynick, % playername, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $name, Ivan, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $family, Ivanov, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $rank1, Рядовой, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $rank2, Ефрейтор, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $drank, % "Ефрейтор", All ; different rank
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $reason, Сдал присягу, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $imgur, <ссылка на скриншот>, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $hour, % A_Hour, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $min, % A_Min, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $sec, % A_Hour, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $day, % A_DD, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $year, % str.right(A_YYYY, 2), All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $month, % A_MM, All
StringReplace, AutoregisterFormatText, AutoregisterFormatText, $action, % "Повышен", All

GuiControl, autoregister_format:, AutoregisterFormatPreview, % AutoregisterFormatText
GuiControl, autoregister_format:, AutoregisterFormatSave, Сохранено.

sleep 3000

GuiControl, autoregister_format:, AutoregisterFormatSave, Сохранить
GuiControl, autoregister_format:enable, AutoregisterFormatSave
return

sortscreenstate:
if !sortscreenstate
{
	Menu, reportHelp, check, Сортировка скриншотов
	sortscreenstate = 1
	IniWrite, 1, config.ini, sortscreen, state
}
else {
	Menu, reportHelp, uncheck, Сортировка скриншотов
	sortscreenstate = 0
	IniWrite, 0, config.ini, sortscreen, state
}
return

loading_uiGuiClose:
exitapp

checkstartreason:
if start_argument1 = debug
	goto debug

return

debug:
debug = 1
console.create()
console.setTitle("GOS Helper Debug Window")

if !A_IsCompiled
	return

if (start_argument2) {
	stdoutcmd := start_argument2
	gosub processSTD
	return
}

console.write("DEBUG | Enter the command to be executed: ")
dbg_start_cmd := console.read()

KeyWait, Enter, U
if (Trim(dbg_start_cmd) = "") {
	return
} else {
	stdoutcmd := dbg_start_cmd
	gosub processorSTD
}
return

processorSTD:
gui, stdout_cmd:destroy

if stdoutcmd contains `&
{
	stdoutcmd_executePseudoMassive := stdoutcmd
	loop, parse, stdoutcmd_executePseudoMassive, `&
	{
		stdoutcmd := Trim(A_LoopField)
		gosub processSTD
	}
	return
}

processSTD:
RegExMatch(stdoutcmd, "i)timer (.*) set (.*)", outproc)
if outproc1
{
	try settimer, % outproc1, % outproc2
	catch e {
		console.writeln("ERROR | processorSTD params (1: " outproc1 ", 2: " outproc2 "): " e.Message)
		return
	}
	
	console.writeln("SUCCESSFUL | processorSTD params (1: " outproc1 ", 2: " outproc2 ").")
	return
}

RegExMatch(stdoutcmd, "i)bind (.*) set (.*)", outproc)
if outproc1
{
	try hotkey, % outproc1, % outproc2
	catch e {
		console.writeln("ERROR | processorSTD params (1: " outproc1 ", 2: " outproc2 "): " e.Message)
		return
	}
	
	console.writeln("SUCCESSFUL | processorSTD params (1: " outproc1 ", 2: " outproc2 ").")
	return
}

RegExMatch(stdoutcmd, "i)variable (.*) set (.*)", outproc)
if outproc1
{
	%outproc1% = %outproc2%
	console.writeln("SUCCESSFUL | processorSTD params (1: " outproc1 ", 2: " outproc2 ").")
	return
}

try gosub %stdoutcmd%
return

_cmd_relog:
dialog.standard("Нажмите на клавиатуре '1' для релога на 01 сервер, '2' для релога на 02 сервер.")
hotkey, 1, 01serv
hotkey, 2, 02serv
hotkey, 1, on
hotkey, 2, on
hotkey, escape, cancelRelog
hotkey, escape, on
hotkey, LButton, cancelRelog
hotkey, LButton, on
return

CancelRelog:
hotkey, 1, off
hotkey, 2, off
hotkey, escape, off
hotkey, LButton, off

dialog.standard("Вы отменили релог.")
return

01serv:
hotkey, 1, off
hotkey, 2, off
hotkey, escape, off
hotkey, LButton, off

process, close, gta_sa.exe
nosync = 1
owc = 0

while game_loaded
	continue

goto start01server

02serv:
hotkey, 1, off
hotkey, 2, off
hotkey, escape, off
hotkey, LButton, off

process, close, gta_sa.exe
nosync = 1
owc = 0

while game_loaded
	continue

goto start02server

gh_main_hk:
IfWinNotActive, ahk_id %mainwid%
	return

if (GetKeyState("F", "P") or (GetKeyState("G", "P"))) {
	sleep 100
	if ((GetKeyState("F", "P")) & GetKeyState("G", "P")) {
		gosub gamepathh
		return
	}
}

if GetKeyState("Ctrl", "P") {
	if GetKeyState("S", "P") { ; Ctrl + S (синхронизировать файлы)
		gosub syncwithgame
		KeyWait, S, U
	}
}

if GetKeyState("M", "P") {
	gosub showMenu
	KeyWait, M, U
}

if GetKeyState("F", "P") { ; открыть папку игры
	gosub openfolder
	KeyWait, G, U
}

if GetKeyState("G", "P") { ; запустить игру
	gosub start_game
	KeyWait, G, U
}

if GetKeyState("S", "P") { ; папка syncwithgame
	gosub auto_copy
	KeyWait, S, U
}

if GetKeyState("P", "P") { ; папка со скриншотами
	gosub open_screen
	KeyWait, S, U
}

if GetKeyState("I", "P") { ; инфа о себе
	gosub aboutme
	KeyWait, S, U
}

if GetKeyState("W", "P") { ; автоотыгровка оружия
	gosub settings_autogunrp
	KeyWait, S, U
}

if GetKeyState("A", "P") { ; Настройки автореестра
	gosub settings_autoregister
	KeyWait, S, U
}
return

hotkeys:
Gui, 1:+OwnDialogs
MsgBox, 0, % title, 
(
Данные горячие клавиши работают только в главном окне GOS Helper'a.

CTRL + S - Синхронизировать папку с игрой, без запуска игры.
F + G - Открыть папку игры.
A - Выполнить: Параметры отыгровок > Настройка функции автореестра
F - Выполнить: Информация о программе > Открыть папку игры.
G - Выполнить: В игру (G).
S - Выполнить: Синхронизация папки с игрой.
P - Выполнить: Папка со скриншотами.
I - Выполнить: Параметры отыгровок > Заполнить информацию о себе.
W - Выполнить: Параметры отыгровок > Настройка автоматической отыгровки оружий.
)
return

antierror:
WinGet, winlist, list
loop, %winlist%
{
	wid := winlist%A_Index%
	WinGet, ProcessNameG, ProcessName, ahk_id %wid%
	
	if (processNameG = "gta_sa.exe") {
		WinGetTitle, processtitleG, ahk_id %wid%
		if processtitleG = error
			WinClose, ahk_id %wid%
	}
}
return

help:
console.writeln("bind [key] set [label]")
console.writeln("timer [label] set [delay]")
console.writeln("variable [variable] set [value]")
return

fractionrp:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")

index = 0
loop files, binders\%fraction2%\*.ini
	index++

if (index = 0) {
	MsgBox, 16, % title, Недоступно для Вашей фракции.
	return
}

Gui, fractionrp:Destroy
Gui, fractionrp:-MinimizeBox +hwndfractionrpwid +AlwaysOnTop
Gui, fractionrp:color, White
Gui, fractionrp:Font, S11 CDefault Bold, Segoe UI
Gui, fractionrp:Add, Text,, Выберите отыгровку
Gui, fractionrp:Font, S9 CDefault norm, Segoe UI

texttmp := ""
loop files, binders\%fraction2%\*.ini, F
{
	SplitPath, A_LoopFileFullPath,,,, filename
	if filename
		texttmp := texttmp "/" filename "|"
}

Gui, fractionrp:Add, ComboBox, vBinderSelected w400, % texttmp
Gui, fractionrp:Add, Text,, Текст отыгровки
Gui, fractionrp:Add, Edit, vBinderText w400 h150, % bindertext

Gui, fractionrp:Font, S9 CGray underline, Segoe UI
Gui, fractionrp:Add, Text, gFractionRP_Vars, Нажмите сюда для списка переменных

Gui, fractionrp:Font, S9 CDefault norm, Segoe UI
Gui, fractionrp:Add, Button, w400 gFractionRP_Save vFractionRP_Save, Запомнить
Gui, fractionrp:Show,, % title

GuiControl, fractionrp:disable, bindertext
GuiControl, fractionrp:disable, FractionRP_Save

settimer, _fractionrp, 100
settimer, __fractionrploop, 1

__fractionrploop:
IfWinNotExist, ahk_id %fractionrpwid%
{
	settimer, __fractionrploop, off
	return
}

IfWinNotActive, ahk_id %fractionrpwid%
	return

if GetKeyState("Escape", "P")
	gui, fractionrp:destroy

return

_fractionrp:
gui, fractionrp:submit, nohide
IfWinNotExist, ahk_id %fractionrpwid%
	settimer, _fractionrp, off

if (obinderselected = binderselected)
	return

obinderselected := binderselected
StringReplace, strplcd, binderselected, `/,,

if (Trim(StrReplace(binderselected, "/")) = "") {
	GuiControl, fractionrp:disable, bindertext
	GuiControl, fractionrp:disable, FractionRP_Save
	
	fileread, bindertext, % "binders\" fraction2 "\" strplcd ".ini"
	GuiControl, fractionrp:, bindertext, % bindertext
	return
}

ifnotexist, % "binders\" fraction2 "\" strplcd ".ini"
{
	GuiControl, fractionrp:disable, bindertext
	GuiControl, fractionrp:disable, FractionRP_Save
}
else {
	GuiControl, fractionrp:enable, bindertext
	GuiControl, fractionrp:enable, FractionRP_Save
}

fileread, bindertext, % "binders\" fraction2 "\" strplcd ".ini"
GuiControl, fractionrp:, bindertext, % bindertext
return

FractionRP_Save:
gui, fractionrp:+OwnDialogs
gui, fractionrp:submit, nohide

if (!strplcd)
	return

filedelete, % "binders\" fraction2 "\" strplcd ".ini"
fileappend, % bindertext, % "binders\" fraction2 "\" strplcd ".ini"

MsgBox, 64, % title, Отыгровка "/%strplcd%" сохранена.
gui, fractionrp:destroy
return

FractionRP_Vars:
gui, fractionrp:+owndialogs
MsgBox, 0, % title, 
(
Стандартные:
$myname - Ваше имя на русском (указано в "Заполнить информацию о себе").
$myfamily - Ваша фамилия на русском (указано в "Заполнить информацию о себе").
$myrank - Ваш ранг (указано в "Заполнить информацию о себе").

Для некоторых ситуаций, где взаимодействие с игроками.
$id - ID игрока (с которым идет взаимодействие).
$name - Имя игрока (с которым идет взаимодействие).
$family - Фамилия игрока (с которым идет взаимодействие).

Для выдачи штрафов
$reason - причина выдачи.
$sum - сумма штрафа.

Для СМИ:
$theme - тема эфира.
$place - место сбора (когда нужен денежный фонд). Например, Банк Арзамаса.
)
return

deinstall:
RegRead, path, HKEY_LOCAL_MACHINE, SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\GOSHELPER, UninstallString
Run, %path% /deinstall,, UseErrorLevel
if errorlevel
{
	Gui, +OwnDialogs
	MsgBox, 0, GOS Helper, Пожалуйста`, установите программу через установщик.
	exitapp
}
return

reinstall:
RegRead, path, HKEY_LOCAL_MACHINE, SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\GOSHELPER, UninstallString
Run, %path% /reinstall,, UseErrorLevel
if errorlevel
{
	Gui, +OwnDialogs
	MsgBox, 0, GOS Helper, Пожалуйста`, установите программу через установщик.
	exitapp
}
return

update:
console.write("INFO | Select what to update (1-installer, 2-kernel): ")
updvar := console.read()

if (Trim(updvar) = 1) {
	need_installer_version := "UPDATE_COMMAND"
	goto setupInstallerCheck
}

if (Trim(updvar) = 2) {
	RegRead, path, HKEY_LOCAL_MACHINE, SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\GOSHELPER, UninstallString
	Run, %path% /update,, UseErrorLevel
	if errorlevel
	{
		Gui, +OwnDialogs
		MsgBox, 0, GOS Helper, Пожалуйста`, установите программу через установщик.
		exitapp
	}
	exitapp
}

console.writeln("An error occurred while executing the command.")
return

exit:
exitapp

_cmd_адвокат1:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")
	
ifnotexist, binders\%fraction2%\адвокат1.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

approximate_expectation = 0
fileread, bText, binders\%fraction2%\адвокат1.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	;StringReplace, textToChat, textToChat, % "$name", % autoregister_name, All
	;StringReplace, textToChat, textToChat, % "$family", % autoregister_family, All
	;StringReplace, textToChat, textToChat, % "$id", % autoregister_id, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
chat.show("%t Имеется продолжение бинда. Используйте %b/адвокат2%w.")
return

_cmd_адвокат2:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")
	
ifnotexist, binders\%fraction2%\адвокат2.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

approximate_expectation = 0
fileread, bText, binders\%fraction2%\адвокат2.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	;StringReplace, textToChat, textToChat, % "$name", % autoregister_name, All
	;StringReplace, textToChat, textToChat, % "$family", % autoregister_family, All
	;StringReplace, textToChat, textToChat, % "$id", % autoregister_id, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
chat.show("%t Имеется продолжение бинда. Используйте %b/адвокат3%w.")
return

_cmd_адвокат3:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")
	
ifnotexist, binders\%fraction2%\адвокат3.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

settimer, chatlogger, off
dynamicbtext_id := chat.input("Укажите ID человека, с которым мы будем взаимодействовать.")
if dynamicbtext_id = -1
	return

chat.send("/id " dynamicbtext_id)
sleep 1500

index = 0
loop {
	haystack := GetChatLine(index)
	RegExMatch(haystack, "Игрок (.*)\_(.*)\[(.*)\]", pname)
	
	dynamicbtext_name := pname1
	dynamicbtext_family := pname2
	index++
	
	if dynamicbtext_name
		break
	
	if index > 9
	{
		chat.show("%t Не найдена информация об игроке. Операция отменена.")
		chat.show("%t Проверьте, может какие-нибудь программы не дают доступ к чатлогу.")
		settimer, chatlogger, on
		return
	}
}

settimer, chatlogger, on

approximate_expectation = 0
fileread, bText, binders\%fraction2%\адвокат3.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	StringReplace, textToChat, textToChat, % "$name", % dynamicbtext_name, All
	StringReplace, textToChat, textToChat, % "$family", % dynamicbtext_family, All
	StringReplace, textToChat, textToChat, % "$id", % dynamicbtext_id, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
return

_cmd_удостоверение:
chat.show("%t Вы можете использовать сокращенный вид команды: %b/уд%w.")

_cmd_уд:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")
	
ifnotexist, binders\%fraction2%\удостоверение.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

settimer, chatlogger, off
dynamicbtext_id := chat.input("Укажите ID человека, с которым мы будем взаимодействовать.")
if dynamicbtext_id = -1
	return

chat.send("/id " dynamicbtext_id)
sleep 2500

index = 0
loop {
	haystack := GetChatLine(index)
	RegExMatch(haystack, "Игрок (.*)\_(.*)\[(.*)\]", pname)
	
	dynamicbtext_name := pname1
	dynamicbtext_family := pname2
	index++
	
	if dynamicbtext_name
		break
	
	if index > 9
	{
		chat.show("%t Не найдена информация об игроке. Операция отменена.")
		chat.show("%t Проверьте, может какие-нибудь программы не дают доступ к чатлогу.")
		settimer, chatlogger, on
		return
	}
}

settimer, chatlogger, on

approximate_expectation = 0
fileread, bText, binders\%fraction2%\удостоверение.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	StringReplace, textToChat, textToChat, % "$name", % dynamicbtext_name, All
	StringReplace, textToChat, textToChat, % "$family", % dynamicbtext_family, All
	StringReplace, textToChat, textToChat, % "$id", % dynamicbtext_id, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
return

_cmd_присяга:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")
	
ifnotexist, binders\%fraction2%\присяга.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

approximate_expectation = 0
fileread, bText, binders\%fraction2%\присяга.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	;StringReplace, textToChat, textToChat, % "$name", % autoregister_name, All
	;StringReplace, textToChat, textToChat, % "$family", % autoregister_family, All
	;StringReplace, textToChat, textToChat, % "$id", % autoregister_id, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
return

_cmd_разборкам4:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")
	
ifnotexist, binders\%fraction2%\разборкам4.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

approximate_expectation = 0
fileread, bText, binders\%fraction2%\разборкам4.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	;StringReplace, textToChat, textToChat, % "$name", % autoregister_name, All
	;StringReplace, textToChat, textToChat, % "$family", % autoregister_family, All
	;StringReplace, textToChat, textToChat, % "$id", % autoregister_id, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
chat.show("%t Для сборки М4 - используйте %b/сборкам4%w.")
return

_cmd_сборкам4:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")
	
ifnotexist, binders\%fraction2%\сборкам4.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

approximate_expectation = 0
fileread, bText, binders\%fraction2%\сборкам4.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	;StringReplace, textToChat, textToChat, % "$name", % autoregister_name, All
	;StringReplace, textToChat, textToChat, % "$family", % autoregister_family, All
	;StringReplace, textToChat, textToChat, % "$id", % autoregister_id, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
return

_cmd_клятва:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")
	
ifnotexist, binders\%fraction2%\клятва.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

approximate_expectation = 0
fileread, bText, binders\%fraction2%\клятва.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	;StringReplace, textToChat, textToChat, % "$name", % autoregister_name, All
	;StringReplace, textToChat, textToChat, % "$family", % autoregister_family, All
	;StringReplace, textToChat, textToChat, % "$id", % autoregister_id, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
return

_cmd_лечить1:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")
	
ifnotexist, binders\%fraction2%\лечить1.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

approximate_expectation = 0
fileread, bText, binders\%fraction2%\лечить1.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	;StringReplace, textToChat, textToChat, % "$name", % autoregister_name, All
	;StringReplace, textToChat, textToChat, % "$family", % autoregister_family, All
	;StringReplace, textToChat, textToChat, % "$id", % autoregister_id, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
chat.show("%t Имеется продолжение бинда. Используйте %b/лечить2%w.")
return

_cmd_лечить2:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")

ifnotexist, binders\%fraction2%\лечить2.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

settimer, chatlogger, off
dynamicbtext_id := chat.input("Укажите ID человека, с которым мы будем взаимодействовать.")
if dynamicbtext_id = -1
	return

chat.send("/id " dynamicbtext_id)
sleep 2500

index = 0
loop {
	haystack := GetChatLine(index)
	RegExMatch(haystack, "Игрок (.*)\_(.*)\[(.*)\]", pname)
	
	dynamicbtext_name := pname1
	dynamicbtext_family := pname2
	index++
	
	if dynamicbtext_name
		break
	
	if index > 9
	{
		chat.show("%t Не найдена информация об игроке. Операция отменена.")
		chat.show("%t Проверьте, может какие-нибудь программы не дают доступ к чатлогу.")
		settimer, chatlogger, on
		return
	}
}

settimer, chatlogger, on

approximate_expectation = 0
fileread, bText, binders\%fraction2%\лечить2.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	StringReplace, textToChat, textToChat, % "$name", % dynamicbtext_name, All
	StringReplace, textToChat, textToChat, % "$family", % dynamicbtext_family, All
	StringReplace, textToChat, textToChat, % "$id", % dynamicbtext_id, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
return

_cmd_лечитьнарко1:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")
	
ifnotexist, binders\%fraction2%\лечитьнарко1.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

approximate_expectation = 0
fileread, bText, binders\%fraction2%\лечитьнарко1.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	;StringReplace, textToChat, textToChat, % "$name", % autoregister_name, All
	;StringReplace, textToChat, textToChat, % "$family", % autoregister_family, All
	;StringReplace, textToChat, textToChat, % "$id", % autoregister_id, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
chat.show("%t Имеется продолжение бинда. Используйте %b/лечитьнарко2%w.")
return

_cmd_лечитьнарко2:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")

ifnotexist, binders\%fraction2%\лечитьнарко2.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

settimer, chatlogger, off
dynamicbtext_id := chat.input("Укажите ID человека, с которым мы будем взаимодействовать.")
if dynamicbtext_id = -1
	return

chat.send("/id " dynamicbtext_id)
sleep 2500

index = 0
loop {
	haystack := GetChatLine(index)
	RegExMatch(haystack, "Игрок (.*)\_(.*)\[(.*)\]", pname)
	
	dynamicbtext_name := pname1
	dynamicbtext_family := pname2
	index++
	
	if dynamicbtext_name
		break
	
	if index > 9
	{
		chat.show("%t Не найдена информация об игроке. Операция отменена.")
		chat.show("%t Проверьте, может какие-нибудь программы не дают доступ к чатлогу.")
		settimer, chatlogger, on
		return
	}
}

settimer, chatlogger, on

approximate_expectation = 0
fileread, bText, binders\%fraction2%\лечитьнарко2.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	StringReplace, textToChat, textToChat, % "$name", % dynamicbtext_name, All
	StringReplace, textToChat, textToChat, % "$family", % dynamicbtext_family, All
	StringReplace, textToChat, textToChat, % "$id", % dynamicbtext_id, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
return

_cmd_лечитьорви:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")

ifnotexist, binders\%fraction2%\лечитьорви.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

settimer, chatlogger, off
dynamicbtext_id := chat.input("Укажите ID человека, с которым мы будем взаимодействовать.")
if dynamicbtext_id = -1
	return

chat.send("/id " dynamicbtext_id)
sleep 2500

index = 0
loop {
	haystack := GetChatLine(index)
	RegExMatch(haystack, "Игрок (.*)\_(.*)\[(.*)\]", pname)
	
	dynamicbtext_name := pname1
	dynamicbtext_family := pname2
	index++
	
	if dynamicbtext_name
		break
	
	if index > 9
	{
		chat.show("%t Не найдена информация об игроке. Операция отменена.")
		chat.show("%t Проверьте, может какие-нибудь программы не дают доступ к чатлогу.")
		settimer, chatlogger, on
		return
	}
}

settimer, chatlogger, on

approximate_expectation = 0
fileread, bText, binders\%fraction2%\лечитьорви.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	StringReplace, textToChat, textToChat, % "$name", % dynamicbtext_name, All
	StringReplace, textToChat, textToChat, % "$family", % dynamicbtext_family, All
	StringReplace, textToChat, textToChat, % "$id", % dynamicbtext_id, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
return

_cmd_лечитьхобл:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")

ifnotexist, binders\%fraction2%\лечитьхобл.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

settimer, chatlogger, off
dynamicbtext_id := chat.input("Укажите ID человека, с которым мы будем взаимодействовать.")
if dynamicbtext_id = -1
	return

chat.send("/id " dynamicbtext_id)
sleep 2500

index = 0
loop {
	haystack := GetChatLine(index)
	RegExMatch(haystack, "Игрок (.*)\_(.*)\[(.*)\]", pname)
	
	dynamicbtext_name := pname1
	dynamicbtext_family := pname2
	index++
	
	if dynamicbtext_name
		break
	
	if index > 9
	{
		chat.show("%t Не найдена информация об игроке. Операция отменена.")
		chat.show("%t Проверьте, может какие-нибудь программы не дают доступ к чатлогу.")
		settimer, chatlogger, on
		return
	}
}

settimer, chatlogger, on

approximate_expectation = 0
fileread, bText, binders\%fraction2%\лечитьхобл.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	StringReplace, textToChat, textToChat, % "$name", % dynamicbtext_name, All
	StringReplace, textToChat, textToChat, % "$family", % dynamicbtext_family, All
	StringReplace, textToChat, textToChat, % "$id", % dynamicbtext_id, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
return

_cmd_лечитьхп:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")

ifnotexist, binders\%fraction2%\лечитьхп.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

settimer, chatlogger, off
dynamicbtext_id := chat.input("Укажите ID человека, с которым мы будем взаимодействовать.")
if dynamicbtext_id = -1
	return

chat.send("/id " dynamicbtext_id)
sleep 2500

index = 0
loop {
	haystack := GetChatLine(index)
	RegExMatch(haystack, "Игрок (.*)\_(.*)\[(.*)\]", pname)
	
	dynamicbtext_name := pname1
	dynamicbtext_family := pname2
	index++
	
	if dynamicbtext_name
		break
	
	if index > 9
	{
		chat.show("%t Не найдена информация об игроке. Операция отменена.")
		chat.show("%t Проверьте, может какие-нибудь программы не дают доступ к чатлогу.")
		settimer, chatlogger, on
		return
	}
}

settimer, chatlogger, on

approximate_expectation = 0
fileread, bText, binders\%fraction2%\лечитьхп.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	StringReplace, textToChat, textToChat, % "$name", % dynamicbtext_name, All
	StringReplace, textToChat, textToChat, % "$family", % dynamicbtext_family, All
	StringReplace, textToChat, textToChat, % "$id", % dynamicbtext_id, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
return

_cmd_арест:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")

ifnotexist, binders\%fraction2%\арест.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

settimer, chatlogger, off
dynamicbtext_id := chat.input("Укажите ID человека, с которым мы будем взаимодействовать.")
if dynamicbtext_id = -1
	return

chat.send("/id " dynamicbtext_id)
sleep 2500

index = 0
loop {
	haystack := GetChatLine(index)
	RegExMatch(haystack, "Игрок (.*)\_(.*)\[(.*)\]", pname)
	
	dynamicbtext_name := pname1
	dynamicbtext_family := pname2
	index++
	
	if dynamicbtext_name
		break
	
	if index > 9
	{
		chat.show("%t Не найдена информация об игроке. Операция отменена.")
		chat.show("%t Проверьте, может какие-нибудь программы не дают доступ к чатлогу.")
		settimer, chatlogger, on
		return
	}
}

settimer, chatlogger, on

approximate_expectation = 0
fileread, bText, binders\%fraction2%\арест.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	StringReplace, textToChat, textToChat, % "$name", % dynamicbtext_name, All
	StringReplace, textToChat, textToChat, % "$family", % dynamicbtext_family, All
	StringReplace, textToChat, textToChat, % "$id", % dynamicbtext_id, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
return

_cmd_взять:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")

ifnotexist, binders\%fraction2%\взять.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

settimer, chatlogger, off
dynamicbtext_id := chat.input("Укажите ID человека, с которым мы будем взаимодействовать.")
if dynamicbtext_id = -1
	return

chat.send("/id " dynamicbtext_id)
sleep 2500

index = 0
loop {
	haystack := GetChatLine(index)
	RegExMatch(haystack, "Игрок (.*)\_(.*)\[(.*)\]", pname)
	
	dynamicbtext_name := pname1
	dynamicbtext_family := pname2
	index++
	
	if dynamicbtext_name
		break
	
	if index > 9
	{
		chat.show("%t Не найдена информация об игроке. Операция отменена.")
		chat.show("%t Проверьте, может какие-нибудь программы не дают доступ к чатлогу.")
		settimer, chatlogger, on
		return
	}
}

settimer, chatlogger, on

approximate_expectation = 0
fileread, bText, binders\%fraction2%\взять.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	StringReplace, textToChat, textToChat, % "$name", % dynamicbtext_name, All
	StringReplace, textToChat, textToChat, % "$family", % dynamicbtext_family, All
	StringReplace, textToChat, textToChat, % "$id", % dynamicbtext_id, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
return

_cmd_кпут:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")

ifnotexist, binders\%fraction2%\кпут.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

settimer, chatlogger, off
dynamicbtext_id := chat.input("Укажите ID человека, с которым мы будем взаимодействовать.")
if dynamicbtext_id = -1
	return

chat.send("/id " dynamicbtext_id)
sleep 2500

index = 0
loop {
	haystack := GetChatLine(index)
	RegExMatch(haystack, "Игрок (.*)\_(.*)\[(.*)\]", pname)
	
	dynamicbtext_name := pname1
	dynamicbtext_family := pname2
	index++
	
	if dynamicbtext_name
		break
	
	if index > 9
	{
		chat.show("%t Не найдена информация об игроке. Операция отменена.")
		chat.show("%t Проверьте, может какие-нибудь программы не дают доступ к чатлогу.")
		settimer, chatlogger, on
		return
	}
}

settimer, chatlogger, on

approximate_expectation = 0
fileread, bText, binders\%fraction2%\кпут.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	StringReplace, textToChat, textToChat, % "$name", % dynamicbtext_name, All
	StringReplace, textToChat, textToChat, % "$family", % dynamicbtext_family, All
	StringReplace, textToChat, textToChat, % "$id", % dynamicbtext_id, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
return

_cmd_обыск:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")

ifnotexist, binders\%fraction2%\обыск.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

settimer, chatlogger, off
dynamicbtext_id := chat.input("Укажите ID человека, с которым мы будем взаимодействовать.")
if dynamicbtext_id = -1
	return

chat.send("/id " dynamicbtext_id)
sleep 2500

index = 0
loop {
	haystack := GetChatLine(index)
	RegExMatch(haystack, "Игрок (.*)\_(.*)\[(.*)\]", pname)
	
	dynamicbtext_name := pname1
	dynamicbtext_family := pname2
	index++
	
	if dynamicbtext_name
		break
	
	if index > 9
	{
		chat.show("%t Не найдена информация об игроке. Операция отменена.")
		chat.show("%t Проверьте, может какие-нибудь программы не дают доступ к чатлогу.")
		settimer, chatlogger, on
		return
	}
}

settimer, chatlogger, on

approximate_expectation = 0
fileread, bText, binders\%fraction2%\обыск.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	StringReplace, textToChat, textToChat, % "$name", % dynamicbtext_name, All
	StringReplace, textToChat, textToChat, % "$family", % dynamicbtext_family, All
	StringReplace, textToChat, textToChat, % "$id", % dynamicbtext_id, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
return

_cmd_розыск:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")

ifnotexist, binders\%fraction2%\розыск.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

settimer, chatlogger, off
dynamicbtext_id := chat.input("Укажите ID человека, с которым мы будем взаимодействовать.")
if dynamicbtext_id = -1
	return

dynamicbtext_reason := chat.input("Укажите номер статьи, которую нарушил игрок.")
if dynamicbtext_reason = -1
	return

chat.send("/id " dynamicbtext_id)
sleep 2500

index = 0
loop {
	haystack := GetChatLine(index)
	RegExMatch(haystack, "Игрок (.*)\_(.*)\[(.*)\]", pname)
	
	dynamicbtext_name := pname1
	dynamicbtext_family := pname2
	index++
	
	if dynamicbtext_name
		break
	
	if index > 9
	{
		chat.show("%t Не найдена информация об игроке. Операция отменена.")
		chat.show("%t Проверьте, может какие-нибудь программы не дают доступ к чатлогу.")
		settimer, chatlogger, on
		return
	}
}

settimer, chatlogger, on

approximate_expectation = 0
fileread, bText, binders\%fraction2%\розыск.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	StringReplace, textToChat, textToChat, % "$name", % dynamicbtext_name, All
	StringReplace, textToChat, textToChat, % "$family", % dynamicbtext_family, All
	StringReplace, textToChat, textToChat, % "$id", % dynamicbtext_id, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	StringReplace, textToChat, textToChat, % "$reason", % dynamicbtext_reason, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
return

_cmd_штраф:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")

ifnotexist, binders\%fraction2%\штраф.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

settimer, chatlogger, off
dynamicbtext_id := chat.input("Укажите ID человека, с которым мы будем взаимодействовать.")
if dynamicbtext_id = -1
	return

dynamicbtext_reason := chat.input("Укажите номер статьи, которую нарушил игрок.")
if dynamicbtext_reason = -1
	return

dynamicbtext_sum := chat.input("Укажите сумму штрафа, которую нарушил игрок.")
if dynamicbtext_sum = -1
	return

chat.send("/id " dynamicbtext_id)
sleep 2500

index = 0
loop {
	haystack := GetChatLine(index)
	RegExMatch(haystack, "Игрок (.*)\_(.*)\[(.*)\]", pname)
	
	dynamicbtext_name := pname1
	dynamicbtext_family := pname2
	index++
	
	if dynamicbtext_name
		break
	
	if index > 9
	{
		chat.show("%t Не найдена информация об игроке. Операция отменена.")
		chat.show("%t Проверьте, может какие-нибудь программы не дают доступ к чатлогу.")
		settimer, chatlogger, on
		return
	}
}

settimer, chatlogger, on

approximate_expectation = 0
fileread, bText, binders\%fraction2%\штраф.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	StringReplace, textToChat, textToChat, % "$name", % dynamicbtext_name, All
	StringReplace, textToChat, textToChat, % "$family", % dynamicbtext_family, All
	StringReplace, textToChat, textToChat, % "$id", % dynamicbtext_id, All
	StringReplace, textToChat, textToChat, % "$reason", % dynamicbtext_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	StringReplace, textToChat, textToChat, % "$sum", % dynamicbtext_sum, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
return

_cmd_прлиц:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")

ifnotexist, binders\%fraction2%\прлиц.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

settimer, chatlogger, off
dynamicbtext_id := chat.input("Укажите ID человека, с которым мы будем взаимодействовать.")
if dynamicbtext_id = -1
	return

chat.send("/id " dynamicbtext_id)
sleep 2500

index = 0
loop {
	haystack := GetChatLine(index)
	RegExMatch(haystack, "Игрок (.*)\_(.*)\[(.*)\]", pname)
	
	dynamicbtext_name := pname1
	dynamicbtext_family := pname2
	index++
	
	if dynamicbtext_name
		break
	
	if index > 9
	{
		chat.show("%t Не найдена информация об игроке. Операция отменена.")
		chat.show("%t Проверьте, может какие-нибудь программы не дают доступ к чатлогу.")
		settimer, chatlogger, on
		return
	}
}

settimer, chatlogger, on

approximate_expectation = 0
fileread, bText, binders\%fraction2%\прлиц.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	StringReplace, textToChat, textToChat, % "$name", % dynamicbtext_name, All
	StringReplace, textToChat, textToChat, % "$family", % dynamicbtext_family, All
	StringReplace, textToChat, textToChat, % "$id", % dynamicbtext_id, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
return

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

_cmd_интервью1:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")
	
ifnotexist, binders\%fraction2%\интервью1.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

approximate_expectation = 0
fileread, bText, binders\%fraction2%\интервью1.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	;StringReplace, textToChat, textToChat, % "$name", % autoregister_name, All
	;StringReplace, textToChat, textToChat, % "$family", % autoregister_family, All
	;StringReplace, textToChat, textToChat, % "$id", % autoregister_id, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
chat.show("%t Имеется продолжение бинда. Используйте %b/интервью2%w.")
return

_cmd_интервью2:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")

ifnotexist, binders\%fraction2%\интервью2.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

settimer, chatlogger, off
dynamicbtext_rank := chat.input("Укажите звание гостя.")
if dynamicbtext_rank = -1
	return

dynamicbtext_name := chat.input("Укажите имя гостя.")
if dynamicbtext_name = -1
	return

settimer, chatlogger, on

approximate_expectation = 0
fileread, bText, binders\%fraction2%\интервью2.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	StringReplace, textToChat, textToChat, % "$name", % dynamicbtext_name, All
	StringReplace, textToChat, textToChat, % "$family", % dynamicbtext_family, All
	StringReplace, textToChat, textToChat, % "$rank", % dynamicbtext_rank, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	StringReplace, textToChat, textToChat, % "$name", % dynamicbtext_name, Al
	StringReplace, textToChat, textToChat, % "$mynumber", % number, Al
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
chat.show("%t Имеется продолжение бинда. Используйте %b/интервью3%w.")
return

_cmd_интервью3:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")

ifnotexist, binders\%fraction2%\интервью3.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

settimer, chatlogger, off
dynamicbtext_rank := chat.input("Укажите звание гостя.")
if dynamicbtext_rank = -1
	return

dynamicbtext_name := chat.input("Укажите имя гостя.")
if dynamicbtext_name = -1
	return

settimer, chatlogger, on

approximate_expectation = 0
fileread, bText, binders\%fraction2%\интервью3.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	StringReplace, textToChat, textToChat, % "$name", % dynamicbtext_name, All
	StringReplace, textToChat, textToChat, % "$family", % dynamicbtext_family, All
	StringReplace, textToChat, textToChat, % "$rank", % dynamicbtext_rank, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	StringReplace, textToChat, textToChat, % "$name", % dynamicbtext_name, Al
	StringReplace, textToChat, textToChat, % "$mynumber", % number, Al
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
return

_cmd_погода:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")
	
ifnotexist, binders\%fraction2%\погода.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

approximate_expectation = 0
fileread, bText, binders\%fraction2%\погода.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	;StringReplace, textToChat, textToChat, % "$name", % autoregister_name, All
	;StringReplace, textToChat, textToChat, % "$family", % autoregister_family, All
	;StringReplace, textToChat, textToChat, % "$id", % autoregister_id, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
return

_cmd_эфир1:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")

ifnotexist, binders\%fraction2%\эфир1.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

settimer, chatlogger, off
dynamicbtext_theme := chat.input("Укажите тему эфира.")
if dynamicbtext_theme = -1
	return

dynamicbtext_place := chat.input("Укажите место сбора фонда.")
if dynamicbtext_place = -1
	return

settimer, chatlogger, on

approximate_expectation = 0
fileread, bText, binders\%fraction2%\эфир1.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	;StringReplace, textToChat, textToChat, % "$name", % dynamicbtext_name, All
	;StringReplace, textToChat, textToChat, % "$family", % dynamicbtext_family, All
	;StringReplace, textToChat, textToChat, % "$rank", % dynamicbtext_rank, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	StringReplace, textToChat, textToChat, % "$theme", % dynamicbtext_theme, All
	StringReplace, textToChat, textToChat, % "$place", % dynamicbtext_place, All
	StringReplace, textToChat, textToChat, % "$mynumber", % number, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
chat.show("%t Имеется продолжение бинда. Используйте %b/эфир2%w.")
return

_cmd_эфир2:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")
	
ifnotexist, binders\%fraction2%\погода.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

approximate_expectation = 0
fileread, bText, binders\%fraction2%\погода.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	;StringReplace, textToChat, textToChat, % "$name", % autoregister_name, All
	;StringReplace, textToChat, textToChat, % "$family", % autoregister_family, All
	;StringReplace, textToChat, textToChat, % "$id", % autoregister_id, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
return

_cmd_эфир3:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")
	
ifnotexist, binders\%fraction2%\эфир3.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

approximate_expectation = 0
fileread, bText, binders\%fraction2%\эфир3.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	;StringReplace, textToChat, textToChat, % "$name", % autoregister_name, All
	;StringReplace, textToChat, textToChat, % "$family", % autoregister_family, All
	;StringReplace, textToChat, textToChat, % "$id", % autoregister_id, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
return

_cmd_куфы:
RegExMatch(fraction, "(.*) ((.*))", fraction)
fraction2 := StrReplace(StrReplace(fraction2, "("), ")")

ifnotexist, binders\%fraction2%\куфы.ini
{
	chat.show("%t Недоступно для Вашей фракции.")
	return
}

settimer, chatlogger, off
dynamicbtext_id := chat.input("Укажите ID человека, с которым мы будем взаимодействовать.")
if dynamicbtext_id = -1
	return

chat.send("/id " dynamicbtext_id)
sleep 2500

index = 0
loop {
	haystack := GetChatLine(index)
	RegExMatch(haystack, "Игрок (.*)\_(.*)\[(.*)\]", pname)
	
	dynamicbtext_name := pname1
	dynamicbtext_family := pname2
	index++
	
	if dynamicbtext_name
		break
	
	if index > 9
	{
		chat.show("%t Не найдена информация об игроке. Операция отменена.")
		chat.show("%t Проверьте, может какие-нибудь программы не дают доступ к чатлогу.")
		settimer, chatlogger, on
		return
	}
}

settimer, chatlogger, on

_куфы:
approximate_expectation = 0
fileread, bText, binders\%fraction2%\куфы.ini
loop, parse, bText, `n
{
	textToChat := A_LoopField
	StringReplace, textToChat, textToChat, % "$name", % dynamicbtext_name, All
	StringReplace, textToChat, textToChat, % "$family", % dynamicbtext_family, All
	StringReplace, textToChat, textToChat, % "$id", % dynamicbtext_id, All
	;StringReplace, textToChat, textToChat, % "$action", % autoregister_reason, All
	StringReplace, textToChat, textToChat, % "$myname", % rus_name, All
	StringReplace, textToChat, textToChat, % "$myrank", % rang, All
	StringReplace, textToChat, textToChat, % "$myfamily", % rus_family, All
	
	if (textToChat = "")
		continue
	else
		chat.send(textToChat)
	
	approximate_expectation+=1200
}

sleep %approximate_expectation%
return

autotazer:
if !autotazer
{
	Menu, roleplay_settings, Check, Автоматически надеть наручники после удара тайзером
	IniWrite, 1, config.ini, Roleplay, autotazer
	autotazer = 1
	return
}
else {
	Menu, roleplay_settings, UnCheck, Автоматически надеть наручники после удара тайзером
	IniWrite, 0, config.ini, Roleplay, autotazer
	autotazer = 0
}
return

ShowMenu:
SetTimer, uititle, off
SetTimer, Watch_Hover,off

Menu, Gui, Show

SetTimer, uititle, 1
SetTimer, Watch_Hover,100
return

supportresps:
if !supportresps
{
	Menu, sup_menu, Check, Подсчет ответов
	IniWrite, 1, config.ini, game, supportresps
	supportresps = 1
	hotkey, Numpad0, fpm
	hotkey, Numpad0, on
	return
}
else {
	Menu, sup_menu, UnCheck, Подсчет ответов
	IniWrite, 0, config.ini, game, supportresps
	supportresps = 0
	hotkey, Numpad0, fpm
	hotkey, Numpad0, off
}
return

_cmd_suphelp:
if (!supportresps) {
	chat.show("%t Сначала включите функцию.")
	return
}

dialog.standard("Вы ответили на {4169E1}" supportresp_count "{FFFFFF} вопросов.`nДля быстрого ответа используйте Numpad0.`nДля сброса количества используйте {4169E1}/supclear{FFFFFF}.")
return

_cmd_supclear:
if (!supportresps) {
	chat.show("%t Сначала включите функцию.")
	return
}

supportresp_count = 0
IniWrite, 0, config.ini, game, supportresp_count
chat.show("%t Количество ответов сброшено.")
return

refreshOverlay:
if game_loaded = 0
	settimer, refreshoverlay, off

if ShowOverlay
{
	generated_ov := "{4169E1}GOS Helper{FFFFFF} v" release " | FPS: {4169E1}" GetFrameRate() " {FFFFFF}| Онлайн GH: {4169E1}" gh_online "{FFFFFF} "
	if isPlayerInAnyVehicle()
	{
		generated_ov := generated_ov "| Здоровье Т/С: {4169E1}" Round(getVehicleHealth()) "{FFFFFF}"
	
		if !isPlayerDriver()
			generated_ov := generated_ov " | Скорость Т/С: {4169E1}~" getVehicleSpeed() " {FFFFFF}"
	}
	
	if supportresps
		generated_ov := generated_ov " | Ответов: {4169E1}" supportresp_count "{FFFFFF}"
	
	generated_ov := generated_ov dop_overlay_text
	
	TextSetString(overlay_id, generated_ov)
}
else
	TextSetString(overlay_id, "")

return

ov_allow_support:
if !ov_allow_support
{
	Menu, sup_menu, Check, Показывать оверлей с вопросами
	IniWrite, 1, config.ini, overlay, allow_support
	ov_allow_support = 1
	return
}
else {
	Menu, sup_menu, UnCheck, Показывать оверлей с вопросами
	IniWrite, 0, config.ini, overlay, allow_support
	ov_allow_support = 0
}
return

showoverlay:
ifexist, SyncWithGame\enbseries.ini
{
	MsgBox, 16, % title, Вы не можете включить эту функцию. В сборке установлен ENBSeries. Оверлей GH не совместим с ENB. Включение может привести к крашам игры.
	return
}

if !showoverlay
{
	Menu, game_menu, Check, Показывать оверлей
	IniWrite, 1, config.ini, overlay, showoverlay
	showoverlay = 1
	return
}
else {
	Menu, game_menu, UnCheck, Показывать оверлей
	IniWrite, 0, config.ini, overlay, showoverlay
	showoverlay = 0
}
return

_cmd_ovhelp:
if (!showoverlay) {
	chat.show("%t Сначала включите оверлей.")
	return
}

tmp_text =
(
{4169E1}/ovmove {FFFFFF}- переместить оверлей по экрану.
{4169E1}/ovfont {FFFFFF}- изменить шрифт оверлея.
{4169E1}/ovsize {FFFFFF}- изменить размер шрифта оверлея.
{4169E1}/ovstandard {FFFFFF}- вернуть стандартные настройки оверлея.
)
dialog.standard(tmp_text)
return

_cmd_ovmove:
if (!showoverlay) {
	chat.show("%t Сначала включите оверлей.")
	return
}

dialog.standard("Используйте WASD. Чтобы сохранить изменения - нажмите Space.")
settimer, _ovmove, 1
return

_ovmove:
if GetKeyState("W", "P")
	ovy--

if GetKeyState("A", "P")
	ovx--

if GetKeyState("S", "P")
	ovy++

if GetKeyState("D", "P")
	ovx++

if GetKeyState("Space", "P") {
	settimer, _ovmove, off
	IniWrite, % ovx, config.ini, overlay, ovx
	IniWrite, % ovy, config.ini, overlay, ovy
	dialog.standard("Изменения сохранены.")
}

TextSetPos(overlay_id, ovx, ovy)
return

_cmd_ovfont:
if (!showoverlay) {
	chat.show("%t Сначала включите оверлей.")
	return
}

ovfontname := chat.input("Укажите название установленого шрифта.")
if ovfontname = -1
	return

TextUpdate(overlay_id, ovfontname, ovsize, "false", "false")
IniWrite, % ovfontname, config.ini, overlay, ovfontname
return

_cmd_ovsize:
if (!showoverlay) {
	chat.show("%t Сначала включите оверлей.")
	return
}

ovsize := chat.input("Укажите размер шрифта (сейчас " ovsize ").")
if ovsize = -1
	return

TextUpdate(overlay_id, ovfontname, ovsize, "false", "false")
IniWrite, % ovsize, config.ini, overlay, ovsize
return

_cmd_ovstandard:
if (!showoverlay) {
	chat.show("%t Сначала включите оверлей.")
	return
}

IniDelete, config.ini, overlay, ovx
IniDelete, config.ini, overlay, ovy
IniDelete, config.ini, overlay, ovfontname
IniDelete, config.ini, overlay, ovsize

chat.show("%t Настройки оверлея обнулены. GOS Helper будет перезагружен.")
reload
return

openinstaller:
RegRead, path, HKEY_LOCAL_MACHINE, SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\GOSHELPER, UninstallString
IfNotExist, %path%
{
	ifnotexist, %A_ProgramFiles%\GOS Helper\setup.exe
	{
		MsgBox, 16, % title, По-моему что-то пошло не по плану. Скачайте установщик GH самостоятельно. Я не могу найти его.
		return
	}
	else {
		Run, %A_ProgramFiles%\GOS Helper\setup.exe
	}
	return
}

Run, %path%
return

version:
console.writeln("INFO | " release)
return

_cmd_ghtruck:
if (!ghtruck.getHistory()) {
	chat.show("%t Сначала загрузите/доставьте груз и попробуйте снова.")
	return
}

t := ghtruck.getHistory()
loop, parse, t, `n
	count_ght := A_Index

if count_ght > 20
{
	chat.show("%t Список стал слишком большим. Мы его очистили и оставили только запись о доходе.")
	summarize := ghtruck.summarize()
	ghtruck.dropAll()
	ghtruck.writeHistory(summarize, "Доход за прошлые рейсы")
}

chat.show("%t Текущий доход: " ghtruck.summarize() "Р.")
showdialog(5, "{4169E1}" title, "{FFFFFF}Доходы/расходы`t{FFFFFF}Описание`n`n" ghtruck.getHistory(), "Закрыть")
return

startupbutton:
if startupbutton
{
	Menu, help, UnCheck, Запускать GH вместе с Windows
	filedelete, %A_Startup%\goshelper.lnk
	startupbutton = 0
}
else {
	Menu, help, Check, Запускать GH вместе с Windows
	FileCreateShortcut, %root%\gh.exe minimize, %A_StartUp%\goshelper.lnk
	startupbutton = 1
}
return

__CommandProcessor:
while IsInChat()
	continue

sleep 200
dwAddress := dwSamp + 0x141A78
chatInput := readString(hGTA, dwAddress, 512)

if chatInput not contains `/
	return

if (str.left(chatInput, 1) != "/")
	return

loop, parse, _cmds, `n
{
	cmdfield := "/" A_LoopField
	loop, parse, chatInput, % " "
	{
		if A_Index > 1
			continue
		
		if (str.up(cmdfield) = str.up(A_LoopField)) {
			sleep 500
			writeString(hGTA, dwAddress, "")
			goto, % "_cmd_" StrReplace(A_LoopField, "/")
		}
		
		ifexist, % "individrp\" StrReplace(A_LoopField, "/") ".ini"
		{
			execScript := StrReplace(A_LoopField, "/")
			writeString(hGTA, dwAddress, "")
			goto execute
		}
	}
}
return

not_responding_test:
IfWinNotExist, ahk_exe gta_sa.exe
{
	if nr_show = 1
	{
		settimer, not_responding_true, off
		try hotkey, +escape, off
		ToolTip
		nr_show = 0
		nr_true_timer = 0
	}
	return
}

IfWinNotActive, ahk_exe gta_sa.exe
{
	if nr_show = 1
	{
		settimer, not_responding_true, off
		try hotkey, +escape, off
		ToolTip
		nr_show = 0
		nr_true_timer = 0
	}
	return
}

WinGet, SAMP_WID, ID, ahk_exe gta_sa.exe
Responding := DllCall("SendMessageTimeout", "UInt", SAMP_WID, "UInt", 0x0000, "Int", 0, "Int", 0, "UInt", 0x0002, "UInt", TimeOut, "UInt *", NR_temp)

If Responding = 0 ; 1= responding, 0 = Not Responding
{
	if !nr_true_timer
	{
		nr_true_timer = 1
		settimer, not_responding_true, 15000
	}
}
else {
	settimer, not_responding_true, off
	try hotkey, +escape, off
	ToolTip
	nr_show = 0
	nr_true_timer = 0
}
return

not_responding_true:
WinGet, SAMP_WID, ID, ahk_exe gta_sa.exe
Responding := DllCall("SendMessageTimeout", "UInt", SAMP_WID, "UInt", 0x0000, "Int", 0, "Int", 0, "UInt", 0x0002, "UInt", TimeOut, "UInt *", NR_temp)

If Responding = 0 ; 1= responding, 0 = Not Responding
{
	nr_show = 1
	ToolTip, Игра не отвечает. Возможно ей нужно некоторое время. Если она также не отвечает уже длительное время`, то нажмите Shift+Escape (убьет процесс игры).
	hotkey, +escape, killgame
	hotkey, +escape, on
}
return

killgame:
process, close, gta_sa.exe

settimer, not_responding_true, off
try hotkey, +escape, off
ToolTip
nr_show = 0
nr_true_timer = 0
return

processDialog:
ControlSend,, {space}, ahk_exe gta_sa.exe
sleep 100
dialogInputText := readString(hGTA, dwsamp + 0x141a78, 512)
gosub cancelDialog
return

cancelDialog:
dialogCaptured = 1
ControlSend,, {enter}, ahk_exe gta_sa.exe
return

_commandprocessor:
IfWinNotActive, ahk_exe gta_sa.exe
	return

if (GetKeyState("Enter", "P")) {
	goto __CommandProcessor
}
return

checkEnter:
IfWinNotActive, ahk_exe gta_sa.exe
	return

if (GetKeyState("Enter", "P") or (GetKeyState("NumpadEnter", "P"))) {
	goto processDialog
}

if (GetKeyState("Escape", "P")) {
	goto cancelDialog
}
return

individrp:
Gui, individrp:Destroy
Gui, individrp:-MinimizeBox +hwndindividrpwid
Gui, individrp:Color, White
Gui, individrp:Font, S12 CDefault bold, Segoe UI
Gui, individrp:Add, Text, x12 y9 w450 h30 , Список индивидуальных отыгровок
Gui, individrp:Font, S9 CDefault norm, Segoe UI
Gui, individrp:Add, Button, x12 y339 w140 h30 gCreate_IndividRP, Добавить
Gui, individrp:Add, Button, x162 y339 w140 h30 gEdit_IndividRP, Изменить
Gui, individrp:Add, Button, x312 y339 w150 h30 gDelete_IndividRP, Удалить
Gui, individrp:Add, ListBox, x12 y49 w450 h280 vIndividRP_List, 
Gui, individrp:Show, w479 h379, % title

loop, files, individrp\*.ini
{
	SplitPath, A_LoopFileName,,,, filename
	GuiControl, individrp:, IndividRP_List, % "/" filename
	
	loop, parse, _cmds, `n
	{
		if (Trim(str.up(A_LoopField)) = Trim(str.up(filename))) {
			MsgBox, 48, % title, Отыгровка под именем "/%filename%" не будет работать. Уже существует одноименная встроенная команда.`n`nВстроенные команды в приоритете перед индивидуальными. Придумайте другое название.
		}
	}
}

settimer, _individrploop, 1

_individrploop:
IfWinNotExist, ahk_id %individrpwid%
{
	settimer, _individrploop, off
	return
}

IfWinNotActive, ahk_id %individrpwid%
	return

if GetKeyState("Escape", "P")
{
	gui, individrp:destroy
	KeyWait, Escape, U
}
return

Create_IndividRP:
Gui, Create_IndividRP:Destroy
Gui, Create_IndividRP:-MinimizeBox +hwndCreate_IndividRPwids
Gui, Create_IndividRP:Color, White
Gui, Create_IndividRP:Font, S12 CDefault bold, Segoe UI
Gui, Create_IndividRP:Add, Text, x12 y9 w450 h20 , Процесс создания индивидуальной отыгровки
Gui, Create_IndividRP:Font, S9 CDefault norm, Segoe UI
Gui, Create_IndividRP:Add, GroupBox, x12 y39 w450 h10 , 
Gui, Create_IndividRP:Add, Text, x12 y59 w250 h20 , Команда активации
Gui, Create_IndividRP:Add, Edit, x272 y59 w190 h20 vIndividRP_CMD, 
Gui, Create_IndividRP:Add, Text, x12 y89 w250 h20 , Алгоритм отыгровки
Gui, Create_IndividRP:Add, Edit, x22 y119 w430 h200 vIndividRP_Code, 
Gui, Create_IndividRP:Add, Button, x357 y89 w60 h20 gIndividRP_Import, Импорт
Gui, Create_IndividRP:Add, Button, x422 y89 w40 h20 gIndividRP_Help, ?
Gui, Create_IndividRP:Add, Button, x157 y329 w160 h30 gIndividRP_CreateOK, ОК
Gui, Create_IndividRP:Show, w479 h379, % title
return

Edit_IndividRP:
Gui, individrp:submit, nohide

if (Trim(IndividRP_List) = "")
	return

IndividRP_Path := "individrp\" StrReplace(IndividRP_List, "/") ".ini"
FileRead, IndividRP_Code, % IndividRP_Path

Gui, Edit_IndividRP:Destroy
Gui, Edit_IndividRP:-MinimizeBox +hwndCreate_IndividRPwids
Gui, Edit_IndividRP:Color, White
Gui, Edit_IndividRP:Font, S12 CDefault bold, Segoe UI
Gui, Edit_IndividRP:Add, Text, x12 y9 w450 h20 , Процесс редактирования индивидуальной отыгровки
Gui, Edit_IndividRP:Font, S9 CDefault norm, Segoe UI
Gui, Edit_IndividRP:Add, GroupBox, x12 y39 w450 h10 , 
Gui, Edit_IndividRP:Add, Text, x12 y59 w250 h20 , Команда активации
Gui, Edit_IndividRP:Add, Edit, x272 y59 w190 h20 vIndividRP_CMD +ReadOnly, % IndividRP_List
Gui, Edit_IndividRP:Add, Text, x12 y89 w250 h20 , Алгоритм отыгровки
Gui, Edit_IndividRP:Add, Edit, x22 y119 w430 h200 vIndividRP_Code, % IndividRP_Code
Gui, Edit_IndividRP:Add, Button, x422 y89 w40 h20 gIndividRP_Help, ?
Gui, Edit_IndividRP:Add, Button, x157 y329 w160 h30 gIndividRP_EditOK, ОК
Gui, Edit_IndividRP:Show, w479 h379, % title
return

IndividRP_EditOK:
Gui, Edit_IndividRP:submit, nohide
filedelete, % IndividRP_Path
fileappend, % individrp_code, % IndividRP_Path

Gui, Edit_IndividRP:destroy
MsgBox, 64, % title, Сохранено., 1
goto individrp

IndividRP_CreateOK:
Gui, Create_IndividRP:Submit, NoHide

loop, parse, _cmds, `n
{
	if (Trim(str.up(A_LoopField)) = Trim(str.up(StrReplace(IndividRP_CMD, "/")))) {
		MsgBox, 16, % title, Вы не можете создать отыгровку с таким названием`, так как она уже есть в списке встроенных команд.
		return
	}
}

filedelete, % "individrp\" StrReplace(IndividRP_CMD, "/") ".ini"
fileappend, % individrp_code, % "individrp\" StrReplace(IndividRP_CMD, "/") ".ini"

ifnotexist, % "individrp\" StrReplace(IndividRP_CMD, "/") ".ini"
{
	MsgBox, 16, % title, Не удалось сохранить файл. Пожалуйста`, укажите другое название команды (только буквы, цифры).
	return
}

Gui, Create_IndividRP:destroy
MsgBox, 64, % title, Сохранено., 1
goto individrp

Delete_IndividRP:
Gui, individrp:Submit, NoHide

if (Trim(IndividRP_List) = "")
	return

MsgBox, 52, % title, % "Вы точно хотите удалить отыгровку /" StrReplace(IndividRP_List, "/") "?"
IfMsgBox, No
	return

filedelete, % "individrp\" StrReplace(IndividRP_List, "/") ".ini"
MsgBox, 64, % title, Сохранено., 1
goto individrp

IndividRP_Help:
filedelete, %A_Temp%\individ.txt
fileappend, % ghlang_help, %A_Temp%\individ.txt
Run, %A_Temp%\individ.txt
return

execute:
loop, read, individrp\%execScript%.ini
{
	lineForExecute := A_LoopReadLine
	fileread, temp_vars, temp_vars.tmp
	loop, parse, temp_vars, `n
	{
		RegExMatch(A_LoopField, "(.*)=(.*)", outproc)
		if outproc1
			StringReplace, lineForExecute, lineForExecute, `$%outproc1%, %outproc2%, All
	}
	
	if (str.down(str.left(lineForExecute, 11)) = "chat.show, ") {
		RegExMatch(lineForExecute, "i)chat.show, (.*)", outproc)
		if (outproc1 != "")
		{
			RegExMatch(outproc1, "i)- (.*)_(.*)\[(.*)\]\: (.*)", checkDecline)
			if (checkDecline1) {
				MsgBox, 16, % title, Ошибка на строке #%A_Index%. Не надо писать от чужого лица :(
				break
			}
			
			chat.show(outproc1)
			continue
		}
		else {
			MsgBox, 16, % title, Ошибка на строке #%A_Index%. Не определен текст, который необходимо показать в чате (пустой аргумент).
			break
		}
	}
	
	if (str.down(str.left(lineForExecute, 11)) = "chat.send, ") {
		RegExMatch(lineForExecute, "i)chat.send, (.*), 0", outproc)
		if (outproc1 != "")
		{
			chat.send(outproc1)
			continue
		}
		
		RegExMatch(lineForExecute, "i)chat.send, (.*), 1", outproc)
		if (outproc1 != "")
		{
			chat.send(outproc1, 1)
			continue
		}
		
		RegExMatch(lineForExecute, "i)chat.send, (.*)", outproc)
		if (outproc1 != "")
		{
			chat.send(outproc1)
			continue
		}
		else {
			MsgBox, 16, % title, Ошибка на строке #%A_Index%. Не определен текст, который необходимо отправить в чат (пустой аргумент).
			break
		}
	}
	
	if (str.down(str.left(lineForExecute, 12)) = "chat.input, ") {
		RegExMatch(lineForExecute, "i)chat.input, (.*), (.*), 0", outproc)
		if (outproc1 != "") {
			if (outproc2 != "") {
				execute_result := chat.input(outproc2)
				IniWrite, % execute_result, temp_vars.tmp, variables, % outproc1
				continue
			}
		}
		
		RegExMatch(lineForExecute, "i)chat.input, (.*), (.*), 1", outproc)
		if (outproc1 != "") {
			if (outproc2 != "") {
				execute_result := chat.input(outproc2, 1)
				IniWrite, % execute_result, temp_vars.tmp, variables, % outproc1
				continue
			}
		}
		
		RegExMatch(lineForExecute, "i)chat.input, (.*), (.*)", outproc)
		if (outproc1 != "") {
			if (outproc2 != "") {
				execute_result := chat.input(outproc2)
				IniWrite, % execute_result, temp_vars.tmp, variables, % outproc1
				continue
			}
			else {
				MsgBox, 16, % title, Ошибка на строке #%A_Index%. Не определен текст`, который будет указан в диалоге (пустой аргумент).
				break
			}
		}
		else {
			MsgBox, 16, % title, Ошибка на строке #%A_Index%. Не определено название переменной`, в которую нужно сохранить результат (пустой аргумент).
			break
		}
	}
	
	if (str.down(str.left(lineForExecute, 17)) = "dialog.standard, ") {
		RegExMatch(lineForExecute, "i)dialog.standard, (.*)", outproc)
		if (outproc1 != "")
		{
			dialog.standard(outproc1)
			continue
		}
		else {
			MsgBox, 16, % title, Ошибка на строке #%A_Index%. Не определен текст, который необходимо показать в диалоге (пустой аргумент).
			break
		}
	}
	
	if (str.down(str.left(lineForExecute, 13)) = "dialog.list, ") {
		RegExMatch(lineForExecute, "i)dialog.list, (.*)", outproc)
		if (outproc1 != "")
		{
			dialog.list(outproc1)
			continue
		}
		else {
			MsgBox, 16, % title, Ошибка на строке #%A_Index%. Не определен текст, который необходимо показать в диалоге (пустой аргумент).
			break
		}
	}
	
	if (str.down(str.left(lineForExecute, 7)) = "sleep, ") {
		RegExMatch(lineForExecute, "i)sleep, (.*)", outproc)
		if (outproc1 != "")
		{
			sleep, % outproc1
			continue
		}
		else {
			MsgBox, 16, % title, Ошибка на строке #%A_Index%. Не определена необходимая задержка (пустой аргумент).
			break
		}
	}
	
	if (str.down(str.left(lineForExecute, 18)) == "nickname.getbyid, ") {
		RegExMatch(lineForExecute, "i)nickname.getByID, (.*), (.*)", outproc)
		if (outproc1 != "")
		{
			if (outproc2 != "") {
				settimer, chatlogger, off
				chat.send("/id " outproc2)
				sleep 2000

				_name := "", _family := ""
				index = 0
				loop {
					haystack := GetChatLine(index)
					RegExMatch(haystack, "Игрок (.*)\_(.*)\[(.*)\]", pname)
					
					_name := Trim(pname1)
					_family := Trim(pname2)
					index++
					
					if _name
						break
					
					if index > 9
					{
						chat.show("%t Не найдена информация об игроке. Операция отменена.")
						chat.show("%t Проверьте, может какие-нибудь программы не дают доступ к чатлогу.")
						settimer, chatlogger, on
						break
					}
				}
				
				IniWrite, % _name, temp_vars.tmp, variables, %outproc1%_name
				IniWrite, % _family, temp_vars.tmp, variables, %outproc1%_family
				IniWrite, % _name " " _family, temp_vars.tmp, variables, %outproc1%
				continue
			}
			else {
				MsgBox, 16, % title, Ошибка на строке #%A_Index%. Не определен ID игрока (пустой аргумен).
				break
			}
		}
		else {
			MsgBox, 16, % title, Ошибка на строке #%A_Index%. Не определено название переменной`, в которую нужно записать информацию (пустой аргумент).
			break
		}
	}
	
	if (trim(str.down(str.left(lineForExecute, 10))) = "screenshot") {
		ControlSend,, {F8}, ahk_exe gta_sa.exe
		continue
	}
	
	if (Trim(lineForExecute) = "")
		continue
	
	MsgBox, 16, % title, Ошибка на строке #%A_Index%. Нераспознанная команда (%lineForExecute%).
	break
}

filedelete, temp_vars.tmp
return

uititle:
IfWinActive, ahk_id %mainwid%
{
	if !wactivated
	{
		wactivated = 1
		GuiControl, 1:+c386aff, StartControlHColor
		GuiControl, 1:hide, StartControlHLogo
		GuiControl, 1:show, StartControlHLogo
		GuiControl, 1:, HeaderButtonMinimize, __`n`nСвернуть
		GuiControl, 1:, HeaderButtonClose, x`n`nЗакрыть
	}
}
else {
	if wactivated
	{
		wactivated = 0
		GuiControl, 1:+c4365CB, StartControlHColor
		GuiControl, 1:hide, StartControlHLogo
		GuiControl, 1:show, StartControlHLogo
		GuiControl, 1:, HeaderButtonMinimize, __`n`nСвернуть
		GuiControl, 1:, HeaderButtonClose, x`n`nЗакрыть
	}
}
return

afktime:
if !is_sub
	return

if !afktime
{
	if !showoverlay
	{
		IniWrite, 0, config.ini, game, afktime
		afktime = 0
		
		IfWinActive, ahk_exe gta_sa.exe
			chat.show("%t Необходимо включить оверлей.")
		else
			MsgBox, 16, % title, Сначала включите оверлей.
		
		return
	}

	Menu, subfuncs, Check, Подсчет времени в AFK
	IniWrite, 1, config.ini, game, afktime
	afktime = 1
	return
}
else {
	Menu, subfuncs, UnCheck, Подсчет времени в AFK
	IniWrite, 0, config.ini, game, afktime
	afktime = 0
}
return

refreshAfkOverlay:
IfWinNotActive, ahk_exe gta_sa.exe
	return

IfWinNotExist, ahk_exe gta_sa.exe
{
	settimer, refreshAfkOverlay, Off
	return
}

if isInAFK()
	return

if !afktime
{
	SetTimer, refreshAfkOverlay, off
	TextSetString(afk_overlay_id, "")
	return
}

if not_afk_time_timer_sec < 1
{
	TextSetString(afk_overlay_id, "")
	return
}

if is_authed = 0
{
	TextSetString(afk_overlay_id, "{FFFFFF}Ожидание...")
	return
}

not_afk_time_timer_sec := not_afk_time_timer_sec - 1
TextSetString(afk_overlay_id, "{FFFFFF}Без AFK: {4169E1}" FormatSeconds(not_afk_time_timer_sec) "{FFFFFF}.")
return

checkrefreshAfkOverlayHour:
if (currentHourAfkTime != A_Hour) {
	not_afk_time_timer_sec = 1200
	currentHourAfkTime := A_Hour
}
return

VarARFormatList:
MsgBox, 0, % title, $name - имя того`, кто записывается в реестр.`n$family - фамилия того`, кто записывается в реестр.`n$rank1 - название ранга "ДО".`n$rank2 - название ранга "ПОСЛЕ".`n$reason - причина записи в реестр игрока.`n$imgur - ссылка на имгур.`n$hour - выводит текущий час на этом ПК.`n$min - выводит текущую минуту на этом ПК.`n$sec - выводит текущую секунду на этом ПК.`n$day - отобразит номер дня в месяце (например`, 04).`n$month - отобразит номер текущего месяца (например`, 12).`n$year - отобразит номер текущего года (последние 2 цифры; например: 20).`n$mynick - Ваш ник в игре.`n$action - совершенное действие (Повышен`, Понижен`, Уволен).`n$drank - альтернативный вид записи ранга (избегается слово "Гражданский").
return

IndividRP_Import:
MsgBox, 65, % title, GOS Helper попробует перевести Ваш AHK скрипт на язык GH. GH может перевести только простенькие бинды!
IfMsgBox, Cancel
	return

Gui, Create_IndividRP:Destroy
Gui, IndividRP_IMPORT:Destroy
Gui, IndividRP_IMPORT:Color, White
Gui, IndividRP_IMPORT:Font, S12 CDefault bold, Segoe UI
Gui, IndividRP_IMPORT:Add, Text, x17 y9 w440 h20 +Center, Перевод простого бинда на AHK на язык GH
Gui, IndividRP_IMPORT:Font, S9 CDefault norm, Segoe UI
Gui, IndividRP_IMPORT:Add, GroupBox, x12 y39 w450 h260 , Вставьте содержимое AHK скрипта в поле ниже.
Gui, IndividRP_IMPORT:Add, Edit, x22 y59 w430 h230 vAHKCodeToGH, 
Gui, IndividRP_IMPORT:Add, Button, x152 y309 w170 h30 gEncodeToGH, Перевести
Gui, IndividRP_IMPORT:Show, w479 h354, % title
return

EncodeToGH:
Gui, IndividRP_IMPORT:Submit, NoHide
Gui, IndividRP_IMPORT:+OwnDialogs

encode_gh_result =
encode_gh_command =
encode_gh_log = Журнал ошибок/успехов:
encode_ahk_lines = 0
encode_ahk_labels_detected = 0

ToolTip, Сбор и диагностика данных кода...,,, encode

loop, parse, AHKCodeToGH, `n
{
	encode_ahk_lines+=1
	RegExMatch(A_LoopField, "(.*)\:\:", outencode)
	if outencode1
	{
		hotkey, % outencode1, nul, UseErrorLevel
		hotkey, % outencode1, off, UseErrorLevel
		if errorlevel
			continue
		
		encode_ahk_labels_detected+=1
	}
}

_encodegh_cmd_req:
if (encode_ahk_labels_detected = 0) {
	ToolTip,,,, encode
	InputBox, encode_gh_command, % title, GOS Helper не обнаружил ни одного бинда в Вашем коде. В GH скрипты активируются командами. Придумайте название команды для активации Вашего бинда.
	if errorlevel
		return
}
else {
	if (encode_ahk_labels_detected > 1) {
		ToolTip,,,, encode
		MsgBox, 64, % title, В этом коде объявлено %encode_ahk_labels_detected% горячих клавиш. На языке GH сделано так: каждый бинд - это своя команда. Пожалуйста`, удалите из кода лишние бинды.
		return
	}
	else {
		ToolTip,,,, encode
		InputBox, encode_gh_command, % title, GOS Helper не использует горячие клавиши для активации скриптов. Скрипты активируются командами. Придумайте название команды для активации Вашего бинда.
		if errorlevel
			return
	}
}

if (trim(encode_gh_command) = "")
	return

loop, parse, _cmds, `n
{
	if (Trim(str.up(A_LoopField)) = Trim(str.up(StrReplace(encode_gh_command, "/")))) {
		MsgBox, 16, % title, Вы не можете создать отыгровку с таким названием`, так как она уже есть в списке встроенных команд.
		goto _encodegh_cmd_req
	}
}

loop, parse, AHKCodeToGH, `n
{
	ToolTip, Обработка конструкции кода (%A_Index%/%encode_ahk_lines%)...,,, encode
	if ((trim(A_LoopField) = "") || (trim(A_LoopField) = "{") || (trim(A_LoopField) = "}") || (str.down(trim(A_LoopField)) = "sendmessage, 0x50,, 0x4190419,, a") || (str.down(trim(A_LoopField)) = "return")) {
		encode_gh_log := encode_gh_log "`n[Инфо] Пропускаю строку №" A_Index "."
		continue
	}
	
	RegExMatch(A_LoopField, "(.*)\:\:", outencode)
	if outencode1
	{
		hotkey, % outencode1, nul, UseErrorLevel
		hotkey, % outencode1, off, UseErrorLevel
		if !ErrorLevel
		{
			encode_gh_log := encode_gh_log "`n[Инфо] Пропускаю строку №" A_Index "."
			continue
		}
	}
	
	RegExMatch(A_LoopField, "i)SendInput,(.*)\{enter\}", outencode)
	if outencode1
	{
		RegExMatch(A_LoopField, "i)\{F6\}(.*)\{enter\}", outencode)
		if outencode1
		{
			encode_gh_log := encode_gh_log "`n[Инфо] Распознал строку №" A_Index "."
			encode_gh_result := encode_gh_result "chat.send, " StrReplace(StrReplace(outencode1, "{"), "}") ", 1`n"
			continue
		}
		
		if (Trim(A_LoopField) = "{F8}") {
			encode_gh_log := encode_gh_log "`n[Инфо] Распознал строку №" A_Index "."
			encode_gh_result := encode_gh_result "screenshot"
			continue
		}
		
		if outencode1
		{
			encode_gh_log := encode_gh_log "`n[Инфо] Распознал строку №" A_Index "."
			encode_gh_result := encode_gh_result "chat.send, " StrReplace(StrReplace(outencode1, "{"), "}") ", 1`n"
			continue
		}
	}
	
	RegExMatch(A_LoopField, "i)SendInput (.*)\{enter\}", outencode)
	if outencode1
	{
		if (Trim(A_LoopField) = "{F8}") {
			encode_gh_log := encode_gh_log "`n[Инфо] Распознал строку №" A_Index "."
			encode_gh_result := encode_gh_result "screenshot"
			continue
		}
		
		RegExMatch(A_LoopField, "i)\{F6\}(.*)\{enter\}", outencode)
		if outencode1
		{
			encode_gh_log := encode_gh_log "`n[Инфо] Распознал строку №" A_Index "."
			encode_gh_result := encode_gh_result "chat.send, " StrReplace(StrReplace(outencode1, "{"), "}") ", 1`n"
			continue
		}
	}
	
	RegExMatch(A_LoopField, "i)Sleep,(.*)", outencode)
	if outencode1
	{
		encode_gh_log := encode_gh_log "`n[Инфо] Распознал строку №" A_Index "."
		encode_gh_result := encode_gh_result "sleep, " trim(outencode1) "`n"
		continue
	}
	
	RegExMatch(A_LoopField, "i)Sleep (.*)", outencode)
	if outencode1
	{
		encode_gh_log := encode_gh_log "`n[Инфо] Распознал строку №" A_Index "."
		encode_gh_result := encode_gh_result "sleep, " trim(outencode1) "`n"
		continue
	}
	
	encode_gh_log := encode_gh_log "`n[Ошибка] Не могу определить что означает строка №" A_Index "."
}

ToolTip,,,, encode
MsgBox, 0, % title, % encode_gh_log

gosub Create_IndividRP
GuiControl, Create_IndividRP:, IndividRP_CMD, % encode_gh_command
GuiControl, Create_IndividRP:, IndividRP_Code, % encode_gh_result
return

netcontrol:
Gui, netcontrol:Destroy
Gui, netcontrol:-MinimizeBox +hwndnetcontrolwid
Gui, netcontrol:Color, White
Gui, netcontrol:Font, S9 CDefault, Segoe UI
Gui, netcontrol:Add, Text, x12 y44 w450 h40 , Если у Вас слабый интернет-роутер`, большой пинг в игре или тариф с ограниченным интернетом`, то Вы можете править эти настройки.
Gui, netcontrol:Add, GroupBox, x12 y89 w450 h90 , Обращения к API GH (нет)
Gui, netcontrol:Add, Text, x22 y109 w430 h20 vTextLimitGHAPI, Подсчеты...
Gui, netcontrol:Add, Slider, x22 y139 w430 h30 vGHAPI_Limit +disabled, % GHAPI_Limit
Gui, netcontrol:Add, GroupBox, x12 y189 w450 h90 , Обращения к API VK (vk.com)
Gui, netcontrol:Add, Text, x22 y209 w430 h20 vTextLimitVKAPI, Подсчеты...
Gui, netcontrol:Add, Slider, x22 y239 w430 h30 vVKAPI_Limit, % VKAPI_Limit
Gui, netcontrol:Font, S14 CDefault bold, Segoe UI
Gui, netcontrol:Add, Text, x12 y9 w450 h30 , Параметры ограничений сетевого трафика
Gui, netcontrol:Show, w479 h296, % title

settimer, _netcontrol, 100
return

netcontrolguiescape:
netcontrolguiclose:
gui, netcontrol:destroy
return

_netcontrol:
IfWinNotExist, ahk_id %netcontrolwid%
{
	ToolTip, Сохранение и применение...
	settimer, _netcontrol, off
	IniWrite, % vkapi_limit, config.ini, netcontrol, vkapi_limit
	
	if vkmsg_state = 1
		settimer, vkmsg_loop, % calculateLimit(vkapi_limit)
	
	ToolTip
}

IfWinNotActive, ahk_id %netcontrolwid%
	return

Gui, netcontrol:submit, nohide

limit_ghapi := calculateLimit(ghapi_limit)

if (limit_ghapi < 350)
	rlcom = возможен большой пинг

if ((limit_ghapi < 510) & (limit_ghapi > 340))
	rlcom = рекомендуется

if ((limit_ghapi > 509) & (limit_ghapi < 700))
	rlcom = мелкие пропуски сообщений

if ((limit_ghapi > 699) & (limit_ghapi < 1000))
	rlcom = пропуски, но экономно

if (limit_ghapi > 999)
	rlcom = пропуски, но оч. экономно

GuiControl, netcontrol:, TextLimitGHAPI, Будет отправляться 1 запрос в %limit_ghapi% мс. (%rlcom%)
limit_vkapi := calculateLimit(vkapi_limit)

if (limit_vkapi < 340)
	rrlcom = слишком много

if ((limit_vkapi < 510) & (limit_vkapi > 339))
	rrlcom = рекомендуется

if ((limit_vkapi > 509) & (limit_vkapi < 700))
	rrlcom = пропуски сообщений

if ((limit_vkapi > 699) & (limit_vkapi < 1000))
	rrlcom = пропуски, но экономно

if (limit_vkapi > 999)
	rrlcom = пропуски, но оч. экономно

GuiControl, netcontrol:, TextLimitVKAPI, Будет отправляться 1 запрос в %limit_vkapi% мс. (%rrlcom%)
return

iexplorer_update_check:
MsgBox, 20, % title, Мы обнаружили`, что произошла ошибка при создании объекта "InternetExplorer.Application". Возможно это связано с тем`, что у вас устаревшая версия Internet Explorer. Скачаем новую? Она предусмотрена для 64-разрядной системы и Windows 7 (но и на десятке вроде все работает).
IfMsgBox, yes
{
	Run, http://%host%/iexplore_installer.exe,, UseErrorLevel
	if errorlevel
	{
		Clipboard = http://%host%/iexplore_installer.exe
		MsgBox, 16, % title, Не удалось открыть "http://%host%/iexplore_installer.exe". Ссылка скопирована в буфер обмена`, вставьте ее в адресную строку.
	}
	
	MsgBox, 64, % title, Попробуйте обновить браузер Internet Explorer (ссылка уже скопирована/уже скачивается) и попробовать снова после установки.
	exitapp
}
return

fpm:
if (IsInChat()) {
	SendInput, 0
	return
}

fpm_id := ""
fpm_id := chat.input("Укажите ID игрока.")
if ((Trim(fpm_id) = "") & (trim(fpm_id) = "-1")) {
	chat.show("%t Операция отменена.")
	return
}

SendMessage, 0x50,, 0x4190419,, ahk_exe gta_sa.exe
SendInput, {F6}/pm %fpm_id% Здравствуйте,{space}
return

gamepathh:
Run, %gamepath%,, UseErrorLevel
if errorlevel
{
	MsgBox, 16, % title, Не удалось открыть: %gamepath%.
	return
}
return

_cmd_testsupov:
loop, 5
{
	random, ts_id, 1, 1000
	fileappend, [%A_Hour%:%A_Min%:%A_Sec%] Вопрос от %playername%[%ts_id%]: %A_Index%-й репорт`n, % path_chatlog
	sleep 250
}
return

Autoregister_Insert:
standard_format := "$name_$family | $day.$month.$year | $drank | $action | $reason | $mynick"

if (str.up(AutoregisterFormatText) != str.up(standard_format)) {
	MsgBox, 68, % title, К сожалению`, функция автоматического вставливания реестра не поддерживает Ваш формат записи. Поддерживается только стандартный формат. Поменять формат записи реестра на стандартный?
	IfMsgBox, yes
		IniWrite, % "$name_$family | $day.$month.$year | $drank | $action | $reason | $mynick", config.ini, Autoregister, formatText
	
	ToolTip, Обновление конфига...
	checkConfig()
	ToolTip
	return
}

Gui, GTab:Destroy
Gui, GTab:Color, White
Gui, GTab:+AlwaysOnTop -SysMenu +hwndgtabwid
Gui, GTab:Font, S12 CDefault bold, Segoe UI
Gui, GTab:Add, Text, x12 y9 c4169E1, Вставка реестра в Google Таблицу
Gui, GTab:Font, S9 CDefault norm, Segoe UI
Gui, GTab:Add, Link, x12 w440 h60 vProgress, Инициализация...
Gui, GTab:Show, x100 y100 NA, % title

GuiControl, GTAB:, Progress, Проверка формата реестра...

reg_ok = 0
reg_err = 0
reg_lines = 0

loop, parse, register_text, `r`n
{
	reg_lines+=1
	
	if (Trim(A_LoopField) = "") {
		reg_ok+=1
		continue
	}
	
	RegExMatch(A_LoopField, "\[(.*)\.(.*).(.*)\]", outreg)
	if (outreg1) {
		reg_ok+=1
		continue
	}
	
	RegExMatch(A_LoopField, "(.*) \| (.*) \| (.*) \| (.*) \| (.*) \| (.*)", outreg)
	if ((outreg1) & (outreg2) & (outreg3) & (outreg4) & (outreg5) (outreg6)) {
		reg_ok+=1
	}
	else {
		reg_err+=1
	}
}

if (reg_err > 0) {
	Gui, GTAB:Destroy
	MsgBox, 16, % title, % "Ошибка: " round(percent(reg_err, reg_lines)) "% реестра не было обработано (" reg_err " из " reg_lines " строк).`n`nВозможно, это связано с тем, что до этого Вы использовали другой формат записи реестра.`n`nРешение: переписать старый реестр под новый формат вручную, либо стереть его."
	return
}

GuiControl, GTAB:, Progress, % "Откройте Google Таблицу с реестром Вашей фракции и нажмите на первую незаполненную строку левой кнопкой мыши. После чего, следует нажать Alt+F12 и реестр будет автоматически заполняться."

settimer, check_hotkey_gtab, 1
return

GTABGuiEscape:
GTABGuiClose:
Gui, GTAB:Destroy
try hotkey, F12, off
return

check_hotkey_gtab:
if (GetKeyState("Alt", "P")) {
	if (GetKeyState("F12", "P")) {
		settimer, check_hotkey_gtab, off
		goto activate_gtab
	}
}
return

activate_gtab:
rplc_gtab = `"
loop, parse, register_text, `r`n
{
	if (trim(A_LoopField = "")) {
		continue
	}
	
	ahref = <a href="">
	GuiControl, GTAB:, Progress, % "Парсинг и вставка: " ahref A_LoopField "</a>..."
	
	field := Trim(StrReplace(A_LoopField, rplc_gtab))
	loop, parse, field, `|
	{
		Send, % A_LoopField "{tab}"
		sleep 100
	}
	
	send, {down}{home}
	sleep 100
}

Gui, GTAB:Destroy
return