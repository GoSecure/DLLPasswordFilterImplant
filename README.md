# DLLPasswordFilterImplant

DLLPasswordFilterImplant is a custom password filter DLL that allows the capture of a user's credentials. Each password change event on a domain will trigger the registered DLL in order to exfiltrate the username and new password value prior successfully changing it in the Active Directory (AD).

## Installing

To install the password filter on a system:
* Create the DLL for the targeted architecture. Compile in 32-bit for a 32-bit system and in 64-bit for a 64-bit system.
* Copy the DLL to the Windows installation directory. (Default folder: \Windows\System32)
* Register the password filter by updating the following registry key:
	```
	HKEY_LOCAL_MACHINE
		SYSTEM
			CurrentControlSet
				Control
					Lsa
	```
	If the Notification Packages subkey exists, add the name of your DLL to the existing value data. Do not overwrite the existing values, and do not include the .dll extension.

	If the Notification Packages subkey does not exist, add it, and then specify the name of the DLL for the value data. Do not include the .dll extension.
* Restart the system
	
## Uninstalling

To completely remove the password filter of a system:
* Unregister the password filter by updating the following registry key:
	```
	HKEY_LOCAL_MACHINE
		SYSTEM
			CurrentControlSet
				Control
					Lsa
	```
	In the Notification Packages subkey remove the name of your DLL of the existing value data. Do not remove other existing values.
* Restart the system
* In the Windows installation directory (Default folder: \Windows\System32), find the password filter DLL (DLLPasswordFilterImplant.DLL) and delete the file.
	