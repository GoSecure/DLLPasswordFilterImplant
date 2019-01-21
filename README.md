# DLLPasswordFilterImplant

DLLPasswordFilterImplant is a custom password filter DLL that allows the capture of a user's credentials. Each password change event on a domain will trigger the registered DLL in order to exfiltrate the username and new password value prior successfully changing it in the Active Directory (AD).

For more information about password filters consult [Microsoft's documentation](https://msdn.microsoft.com/en-us/library/windows/desktop/ms721882(v=vs.85).aspx).

## Installing

1. To install the password filter on a system:
* Create the DLL for the targeted architecture. Compile in 32-bit for a 32-bit system and in 64-bit for a 64-bit system.
* Copy the DLL to the Windows installation directory. (Default folder: \Windows\System32)
* Register the password filter by updating the following registry key:
    ```
    HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa
    ```
    If the `Notification Packages` subkey exists, add the name of the DLL ("DLLPasswordFilterImplant" if you didn't rename it) to the existing value data. Do not overwrite the existing values.
    If the subkey does not exist, create it and add the name of the DLL ("DLLPasswordFilterImplant" if you didn't rename it) to the value data.
    **NOTE:** Do not include the `.dll` extension when adding the name of the DLL in the `Notification Packages` subkey.
* Configure the public key to use for encrypting credentials.
    ```
    KEY=key.pem
    # Generate an RSA key and dump its public key. Keep the private key around for decryption
    openssl genrsa -out $KEY 2048

    # Prepare the Windows registry key entry.
    echo 'Windows Registry Editor Version 5.00' > addKey.reg
    echo >> addKey.reg
    echo '[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa]' >> addKey.reg
    # If python2 does not exist, use `python` instead.
    echo "Key=hex:$(openssl rsa -in $KEY -pubout | sed -E '/^\-/d' | base64 -d | python2 -c 'import sys; print(",".join(["{:02x}".format(ord(b)) for b in sys.stdin.read()]))')" >> addKey.reg
    ```
    You can then run `addKey.reg` file to append the raw public key to the registry.
    Note that using asymmetric encryption significantly increases the size of
    the data to exfiltrate due to message padding. There are possible
    improvements to be made to reduce the data overhead.

* Restart the system
[Source](https://msdn.microsoft.com/en-us/library/windows/desktop/ms721766(v=vs.85).aspx)

2. To register the key and the domain for DNS exfiltration:
* Go to the following registry key:
    ```
    HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa
    ```
* Create a string type subkey named "Domain". Specify your domain in the value of that subkey. **Your domain must start with a "." .** (Example value: ".yourdomain.com")

## Decrypting

The encrypted data is padded using OAEP and can be decrypted as follows:

```
# Convert the stitched hex string to raw bytes.
xxd -r -p exfiltrated.hex > raw.bin

# Decrypt using the private key.
openssl rsautl -decrypt -oaep -inkey $KEY -in raw.bin -out decrypted.txt
```

## Uninstalling

To completely remove the password filter of a system:
* Unregister the password filter by updating the following registry key:
    ```
    HKEY_LOCAL_MACHINE SYSTEM\CurrentControlSet\Control\Lsa
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

