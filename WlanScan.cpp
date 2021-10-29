//WlanScan - Trigger scans for wireless networks, show visible networks, and list established connection profiles

#include <Windows.h>
#include <VersionHelpers.h>					//Restricting to Vista+ to use API version 2
#include <Wlanapi.h>						//Wlan functions 
#include <wtypes.h>							//Wlan types
#include <iostream>							//wcout and endl
#include <iomanip>							//setw and left
#include <io.h>								//This and fcntl.h are needed for _setmode call to allow outputting in unicode
#include <fcntl.h>							

#pragma comment(lib, "wlanapi.lib")			//Link against wlanapi.lib for the wlan APIs

using std::wcout;
using std::endl;
using std::left;
using std::setw;

wchar_t version[] = { L"0.0.1" };			//Version, printed in help output

void showhelp();							//Prints the help text
void shownetworks();						//Shows information on visible networks
void triggerscan();							//Triggers a scan on each wireless network interface
bool checkAdmin();							//Function to check if we're an Admin. Decrypted key information requires this

void wlanInit(HANDLE &wlanHandle, PWLAN_INTERFACE_INFO_LIST &interfaces);			//Function to open the Wlan API handle and gets interface info
void wlanCallback(WLAN_NOTIFICATION_DATA *scanNotificationData, PVOID myContext);	//Function to receive callback notifications for the wireless network scanning

//Context to pass along with callbacks
typedef struct _WLAN_CALLBACK_INFO {
	GUID interfaceGUID;
	HANDLE scanEvent;
	DWORD callbackReason;
} WLAN_CALLBACK_INFO;


int wmain(int argc, wchar_t * argv[])
{

	//Set stdout translation to unicode text. This allows us to output unicode characters like \u2713
	_setmode(_fileno(stdout), _O_U16TEXT);
	wcout << endl;
	
	
	//Windows XP is not supported due to differences in the Wlan API. 
	if (!IsWindowsVistaOrGreater())
	{
		wcout << "Operating system must be Windows Vista or newer." << endl;
		return 0;
	}


	//The C++ standard requires that if there are any parameters, the first parameter will be
	//the name used to invoke the program. So argc needs to be greater than one for us to have
	//any parameters. If there aren't any, we should print the help text and exit.
	if (argc < 2)
	{
		showhelp();
		return 0;
	}
	

	//We'll use wcscmp to match parameters passed in against what we support. It returns 0 for exact string matches.
	if (wcscmp(L"/?", argv[1]) == 0)
	{
		showhelp();
	}
	else if (wcscmp(L"shownetworks", argv[1]) == 0)
	{
		shownetworks();
	}
	else if (wcscmp(L"triggerscan", argv[1]) == 0)
	{
		triggerscan();
	}
	else
	{
		//A command line parameter was passed, but it wasn't one we support.
		wcout << "Unrecognized command line. Run /? for help." << endl;
	}		

	return 0;
}

void showhelp()
{
	wcout << "WlanScan - A small utility for triggering scans for wireless networks\n"
		<< "\n"
		<< "\ttriggerscan \tTriggers a scan for wireless networks\n"
		<< "\tshownetworks \tShows visible wireless networks\n"
		<< "\n";
	return;
}

void wlanInit(HANDLE &wlanHandle, PWLAN_INTERFACE_INFO_LIST &interfaces)
{
	HRESULT result = 0;								//HRESULT to store the return value from Wlan API calls
	DWORD negotiatedVersion = 0;					//DWORD for the Wlan API to store the negotiated API version in

	//Open a handle to the Wlan API
	result = WlanOpenHandle(
		WLAN_API_VERSION_2_0,						//Request API version 2.0
		NULL,										//Reserved
		&negotiatedVersion,							//Address of the DWORD to store the negotiated version
		&wlanHandle									//Address of the HANDLE to store the Wlan handle
		);

	//If the result isn't NO_ERROR, something went wrong. Print the error message and error code, then exit.
	if (result != NO_ERROR)
	{
		wcout << "Error encountered. Code: " << result << endl;
		ExitProcess(result);
	}


	//Enumerate the wireless network interfaces
	result = WlanEnumInterfaces(
		wlanHandle,									//The HANDLE returned by WlanOpenHandle
		NULL,										//Reserved
		&interfaces									//Address of the pointer to store the location to the interface data in
		);

	//If the result isn't NO_ERROR, something went wrong. Print the error message and error code, then exit.
	if (result != NO_ERROR)
	{
		wcout << "Error encountered. Code: " << result << endl;
		ExitProcess(result);
	}


	//Let's output that there are 0, 1 or # interfaces on the system
	//dwNumberOfItems is included in the WLAN_INTERFACE_INFO_LIST we got from WlanEnumInterfaces
	/*if (interfaces->dwNumberOfItems == 0)
	{
		wcout << "There are no wireless interfaces available." << endl;
	}
	else if (interfaces->dwNumberOfItems == 1)
	{
		wcout << "There is 1 wireless interface available." << endl << endl;
	}
	else
	{
		wcout << "There are " << interfaces->dwNumberOfItems << " wireless interfaces available." << endl << endl;
	}*/

	return;

}

void shownetworks()
{
	HRESULT result = 0;								//HRESULT to store the result of Wlan API calls
	HANDLE wlanHandle = NULL;						//HANDLE to the Wlan API
	PWLAN_INTERFACE_INFO_LIST interfaces = nullptr;	//PWLAN_INTERFACE_INFO_LIST pointer for the interface data returned by the Wlan API

	//Get the Wlan API handle and interface info
	wlanInit(wlanHandle, interfaces);

	//For each interface on the system, we'll print the name and number.
	for (ULONG i = 0; i < interfaces->dwNumberOfItems; i++)
	{
		wcout << "Interface " << i + 1 << ": " << interfaces->InterfaceInfo[i].strInterfaceDescription << endl;

		wcout << endl;

		PWLAN_BSS_LIST networksBssList = nullptr;

		result = WlanGetNetworkBssList(
			wlanHandle,
			&(interfaces->InterfaceInfo[i].InterfaceGuid),
			NULL,
			dot11_BSS_type_any,
			true,
			NULL,
			&networksBssList
		);

		if (result != NO_ERROR)
		{
			wcout << "\tError encountered. Code: " << result << endl;
			continue;
		}

		wcout << "\t" << setw(20) << left << "SSID" << setw(24) << left << "BSSID" << setw(14) << left << "RSSI" << endl;
		wcout << "\t" << setw(20) << left << "----------------" << setw(24) << left << "------------------" << setw(14) << left << "-----" << endl;
		for (ULONG num = 0; num < networksBssList->dwNumberOfItems; num++)
		{
			wchar_t networkSSID[255] = { L'\0' };
			for (ULONG a = 0; a < networksBssList->wlanBssEntries[num].dot11Ssid.uSSIDLength; a++)
			{
				networkSSID[a] = btowc(networksBssList->wlanBssEntries[num].dot11Ssid.ucSSID[a]);
			}

			//wcout << "\t" << setw(40) << left << networkSSID << setw(12) << left << networksBssList->wlanBssEntries[num].dot11Bssid << setw(12) << networksBssList->wlanBssEntries[num].lRssi << endl;
			char Mac[512];
			sprintf_s(Mac, "%02x-%02x-%02x-%02x-%02x-%02x",
				networksBssList->wlanBssEntries[num].dot11Bssid[0],
				networksBssList->wlanBssEntries[num].dot11Bssid[1],
				networksBssList->wlanBssEntries[num].dot11Bssid[2],
				networksBssList->wlanBssEntries[num].dot11Bssid[3],
				networksBssList->wlanBssEntries[num].dot11Bssid[4],
				networksBssList->wlanBssEntries[num].dot11Bssid[5]);
			wcout << "\t" << setw(20) << left << networkSSID << setw(24) << left << Mac << setw(14) << left << networksBssList->wlanBssEntries[num].lRssi << endl;
		}
		wcout << endl;
		WlanFreeMemory(networksBssList);

	}


	//Let's free the memory the Wlan API allocated for us and close the handle we opened
	WlanFreeMemory(interfaces);						//Pointer to the PWLAN_WLAN_INTERFACE_INFO_LIST data
	WlanCloseHandle(wlanHandle, NULL);				//The Wlan HANDLE and a Reserved value

	return;
}

bool checkAdmin()
{
	BOOL isAdmin = FALSE;											//Bool to store the result of our check in
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;	//The authority the Administrators group sits under
	PSID AdministratorsGroup = nullptr;								//Pointer to the SID we'll be testing against

	
	AllocateAndInitializeSid(										//Get an SID representing the Administrators group to test against
		&NtAuthority,												//The authority is NtAuthority
		2,															//We have two groups to include
		SECURITY_BUILTIN_DOMAIN_RID,								//Domain admins
		DOMAIN_ALIAS_RID_ADMINS,									//And their alias
		0, 0, 0, 0, 0, 0,											//We don't need the other slots
		&AdministratorsGroup);										//Where the SID should be stored
	
	if (AdministratorsGroup == nullptr)
	{
		//Something went wrong getting our SID. Assume we're not an Administrator
		return false;
	}

	//Check whether our token is part of the Administrators group. If the function fails, assume we're not an Administrator
	if (!CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin))
	{
		FreeSid(AdministratorsGroup);
		return false;
	}

	//We have the answer now in isAdmin, so free the SID we got
	FreeSid(AdministratorsGroup);

	if (isAdmin)
	{
		return true;
	}
	else
	{
		return false;
	}
}

void triggerscan()
{
	HRESULT result = 0;								//HRESULT to store the result of Wlan API calls
	HANDLE wlanHandle = NULL;						//HANDLE to the WLAN api
	PWLAN_INTERFACE_INFO_LIST interfaces = nullptr;	//PWLAN_INTERFACE_INFO_LIST pointer for the interface data returned by the Wlan API

	wlanInit(wlanHandle, interfaces);				//Get the Wlan API handle and interface info

	//For each interface on the system, we'll print the name and number.
	for (ULONG i = 0; i < interfaces->dwNumberOfItems; i++)
	{
		wcout << "Interface " << i + 1 << ": " << interfaces->InterfaceInfo[i].strInterfaceDescription << endl;

		//Declare the callback parameter struct
		WLAN_CALLBACK_INFO callbackInfo = { 0 };
		callbackInfo.interfaceGUID = interfaces->InterfaceInfo[i].InterfaceGuid;

		//Create an event to be triggered in the scan case
		callbackInfo.scanEvent = CreateEvent(
			nullptr,
			FALSE, 
			FALSE, 
			nullptr);


		//Register for wlan scan notifications
		WlanRegisterNotification(wlanHandle, 
			WLAN_NOTIFICATION_SOURCE_ALL, 
			TRUE, 
			(WLAN_NOTIFICATION_CALLBACK)wlanCallback, 
			(PVOID)&callbackInfo, 
			NULL, 
			NULL);
				

		//Start a scan. If the WlanScan call fails, log the error
		WlanScan(wlanHandle, &(interfaces->InterfaceInfo[i].InterfaceGuid), NULL, NULL, NULL);
		if (GetLastError() != ERROR_SUCCESS)
		{
			wcout << "\tError triggering scan on interface " << i + 1 << ". Error: " << GetLastError() << endl;
			continue;
		}
		else
		{
			//Scan request successfully sent
			wcout << "\tScan request sent. Waiting for reply." << endl;
		}

				
		//Wait for the event to be signaled, or an error to occur. Don't wait longer than 15 seconds.
		DWORD waitResult = WaitForSingleObject(callbackInfo.scanEvent, 15000);

		//Check how we got here, via callback or timeout
		if (waitResult == WAIT_OBJECT_0) 
		{
			if (callbackInfo.callbackReason == wlan_notification_acm_scan_complete) 
			{
				wcout << "\tReply: The scan for networks has completed." << endl;
			}
			else if (callbackInfo.callbackReason == wlan_notification_acm_scan_fail)
			{
				wcout << "\tReply: The scan for connectable networks failed." << endl;
			}

			
		}
		else if (waitResult == WAIT_TIMEOUT)
		{
			wcout << "\tError: No response was received after 15 seconds." << endl;
			wcout << "\n\tWindows Logo certified wireless drivers are required to complete scans\n"
				  << "\tin under four seconds, so there may be something wrong." << endl << endl;
		}
		else 
		{
			wcout << "\n\tUnknown error waiting for response. Error Code: " << waitResult << endl << endl;
		}

		wcout << endl;
	}
	
	//Let's free the memory the Wlan API allocated for us and close the handle we opened
	WlanFreeMemory(interfaces);						//Pointer to the PWLAN_WLAN_INTERFACE_INFO_LIST data
	WlanCloseHandle(wlanHandle, NULL);				//The Wlan HANDLE and a Reserved value
	return;
}

void wlanCallback(WLAN_NOTIFICATION_DATA *scanNotificationData, PVOID myContext)
{
	//Get the data from my struct. If it's null, nothing to do
	WLAN_CALLBACK_INFO* callbackInfo = (WLAN_CALLBACK_INFO*)myContext;
	if (callbackInfo == nullptr) 
	{
		return;
	}

	//Check the GUID in the struct against the GUID in the notification data, return if they don't match
	if (memcmp(&callbackInfo->interfaceGUID, &scanNotificationData->InterfaceGuid, sizeof(GUID)) != 0) 
	{
		return;
	}

	//If the notification was for a scan complete or failure then we need to set the event
	if ((scanNotificationData->NotificationCode == wlan_notification_acm_scan_complete) || (scanNotificationData->NotificationCode == wlan_notification_acm_scan_fail))
	{
		//Set the notification code as the callbackReason
		callbackInfo->callbackReason = scanNotificationData->NotificationCode;

		//Set the event
		SetEvent(callbackInfo->scanEvent);
	}
	
	return;	
}