# DLLPasswordFilterImplant

DLLPasswordFilterImplant is a custom password filter DLL that allows the capture of a user's credentials. Each password change event on a domain will trigger the registered DLL in order to exfiltrate the username and new password value prior successfully changing it in the Active Directory (AD).

For more information about password filters consult [Microsoft's documentation](https://msdn.microsoft.com/en-us/library/windows/desktop/ms721882(v=vs.85).aspx).


## Installing

1. To install the password filter on a system:
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
	If the Notification Packages subkey exists, add the name of the DLL ("DLLPasswordFilterImplant" if you didn't rename it) to the existing value data. Do not overwrite the existing values.

	If the Notification Packages subkey does not exist, add it, and then add the name of the DLL ("DLLPasswordFilterImplant" if you didn't rename it) to the value data.
	
	*Do not include the ".dll" extension when adding the name of the DLL in the Notification Packages subkey.*
	
* Restart the system
	
	
[Source](https://msdn.microsoft.com/en-us/library/windows/desktop/ms721766(v=vs.85).aspx)
	
	
2. To register the key and the domain for DNS exfiltration:
* Go to the following registry key:
	```
	HKEY_LOCAL_MACHINE
		SYSTEM
			CurrentControlSet
				Control
					Lsa
	```
* Create a string type subkey named "Key". Specify the key you want the DLL to use for encryption. If the key is shorter than the data to encrypt, the key will be repeated.
* Create a string type subkey named "Domain". Specify your domain in the value of that subkey. *Your domain must start with a '.'.* (Example value: ".yourdomain.com")
	
	
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
	In the Notification Packages subkey remove the name of the DLL of the existing value data. Do not remove other existing values.

* Restart the system
* In the Windows installation directory (Default folder: \Windows\System32), find the password filter DLL ("DLLPasswordFilterImplant.DLL" if you didn't rename it) and delete the file.


## Compatibility

Works on:
* Windows 7 Hosts (x64)
* Windows 10 Hosts (x64)
* Windows Server 2008 DCs (x64)
* Windows Server 2012 DCs (x64)
* Windows Server 2016 DCs (x64)


The password filter was tested exclusively on systems listed above.


## Debug

Here are some tool that may help you debug the DLL (if necessary):
* [Process Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer)
* [Dependency Walker](http://www.dependencywalker.com/)