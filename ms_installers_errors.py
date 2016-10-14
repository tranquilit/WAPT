#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------
#    This file is part of WAPT
#    Copyright (C) 2013  Tranquil IT Systems http://www.tranquil.it
#    WAPT aims to help Windows systems administrators to deploy
#    setup and update applications on users PC.
#
#    WAPT is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    WAPT is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with WAPT.  If not, see <http://www.gnu.org/licenses/>.
#
# -----------------------------------------------------------------------
__version__ = "1.3.7"


# from https://support.microsoft.com/en-us/kb/290158

msi_errors = """\
Error code               Value  Description
---------------------------------------------------------------------------
ERROR_SUCCESS               0   Action completed successfully.
ERROR_INVALID_DATA         13   The data is invalid.
ERROR_INVALID_PARAMETER    87   One of the parameters was invalid.
ERROR_INSTALL_SERVICE_
 FAILURE                 1601   The Windows Installer service could not be
                                accessed. Contact your support personnel
                                to verify that the Windows Installer
                                service is properly registered.
ERROR_INSTALL_USEREXIT   1602   User cancel installation.
ERROR_INSTALL_FAILURE    1603   Fatal error during installation.
ERROR_INSTALL_SUSPEND    1604   Installation suspended, incomplete.
ERROR_UNKNOWN_PRODUCT    1605   This action is only valid for products that
                                are currently installed.
ERROR_UNKNOWN_FEATURE    1606   Feature ID not registered.
ERROR_UNKNOWN_COMPONENT  1607   Component ID not registered.
ERROR_UNKNOWN_PROPERTY   1608   Unknown property.
ERROR_INVALID_HANDLE_
 STATE                   1609   Handle is in an invalid state.
ERROR_BAD_CONFIGURATION  1610   The configuration data for this product is
                                corrupt. Contact your support personnel.
ERROR_INDEX_ABSENT       1611   Component qualifier not present.
ERROR_INSTALL_SOURCE_
 ABSENT                  1612   The installation source for this product
                                is not available. Verify that the source
                                exists and that you can access it.
ERROR_INSTALL_PACKAGE_
 VERSION                 1613   This installation package cannot be
                                installed by the Windows Installer
                                service. You must install a Windows
                                service pack that contains a newer version
                                of the Windows Installer service.
ERROR_PRODUCT_
 UNINSTALLED             1614   Product is uninstalled.
ERROR_BAD_QUERY_SYNTAX   1615   SQL query syntax invalid or unsupported.
ERROR_INVALID_FIELD      1616   Record field does not exist.

ERROR_INSTALL_ALREADY_
 RUNNING                 1618   Another installation is already in
                                progress. Complete that installation
                                before proceeding with this install.
ERROR_INSTALL_PACKAGE_
 OPEN_FAILED             1619   This installation package could not be
                                opened. Verify that the package exists and
                                that you can access it, or contact the
                                application vendor to verify that this is
                                a valid Windows Installer package.
ERROR_INSTALL_PACKAGE_
 INVALID                 1620   This installation package could not be
                                opened. Contact the application vendor to
                                verify that this is a valid Windows
                                Installer package.
ERROR_INSTALL_UI_
 FAILURE                 1621   There was an error starting the Windows
                                Installer service user interface. Contact
                                your support personnel.
ERROR_INSTALL_LOG_
 FAILURE                 1622   Error opening installation log file.
                                Verify that the specified log file
                                location exists and is writable.
ERROR_INSTALL_LANGUAGE_
 UNSUPPORTED             1623   This language of this installation package
                                is not supported by your system.
ERROR_INSTALL_TRANSFORM_
  FAILURE                1624   Error applying transforms. Verify that
                                the specified transform paths are valid.
ERROR_INSTALL_PACKAGE_
 REJECTED                1625   This installation is forbidden by system
                                policy. Contact your system administrator.
ERROR_FUNCTION_NOT_
 CALLED                  1626   Function could not be executed.
ERROR_FUNCTION_FAILED    1627   Function failed during execution.
ERROR_INVALID_TABLE      1628   Invalid or unknown table specified.
ERROR_DATATYPE_MISMATCH  1629   Data supplied is of wrong type.
ERROR_UNSUPPORTED_TYPE   1630   Data of this type is not supported.
ERROR_CREATE_FAILED      1631   The Windows Installer service failed to
                                start. Contact your support personnel.
ERROR_INSTALL_TEMP_
 UNWRITABLE              1632   The temp folder is either full or
                                inaccessible. Verify that the temp folder
                                exists and that you can write to it.
ERROR_INSTALL_PLATFORM_
 UNSUPPORTED             1633   This installation package is not supported
                                on this platform. Contact your application
                                vendor.
ERROR_INSTALL_NOTUSED    1634   Component not used on this machine.
ERROR_PATCH_PACKAGE_
 OPEN_FAILED             1635   This patch package could not be opened.
                                Verify that the patch package exists and
                                that you can access it, or contact the
                                application vendor to verify that this is
                                a valid Windows Installer patch package.
ERROR_PATCH_PACKAGE_
 INVALID                 1636   This patch package could not be opened.
                                Contact the application vendor to verify
                                that this is a valid Windows Installer
                                patch package.
ERROR_PATCH_PACKAGE_
 UNSUPPORTED             1637   This patch package cannot be processed by
                                the Windows Installer service. You must
                                install a Windows service pack that
                                contains a newer version of the Windows
                                Installer service.
ERROR_PRODUCT_VERSION    1638   Another version of this product is already
                                installed. Installation of this version
                                cannot continue. To configure or remove
                                the existing version of this product, use
                                Add/Remove Programs on the Control Panel.
ERROR_INVALID_COMMAND_
 LINE                    1639   Invalid command line argument. Consult the
                                Windows Installer SDK for detailed command
                                line help.
ERROR_INSTALL_REMOTE_
  DISALLOWED             1640   Installation from a Terminal Server
                                client session not permitted for
                                current user.
ERROR_SUCCESS_REBOOT_
  INITIATED              1641   The installer has started a reboot.
                                This error code not available
                                on Windows Installer version 1.0.
ERROR_PATCH_TARGET_
  NOT_FOUND              1642   The installer cannot install the
                                upgrade patch because the program
                                being upgraded may be missing, or the
                                upgrade patch updates a different
                                version of the program. Verify that
                                the program to be upgraded exists on
                                your computer and that you have the
                                correct upgrade patch.

                                This error code is not available on
                                Windows Installer version 1.0.
ERROR_SUCCESS_REBOOT_
 REQUIRED                3010   A restart is required to complete the
                                install. This does not include installs
                                where the ForceReboot action is run. Note
                                that this error will not be available until
                                future version of the installer.
"""

# from https://support.microsoft.com/en-us/kb/938205
wsus_success_codes = """\
0x240001 WU_S_SERVICE_STOP WindowsUpdate Windows Update Agent was stopped successfully
0x00240002 WU_S_SELFUPDATE Windows Update Agent updated itself
0x00240003 WU_S_UPDATE_ERROR Operation completed successfully but there were errors applying the updates
0x00240004 WU_S_MARKED_FOR_DISCONNECT A callback was marked to be disconnected later because the request to disconnect the operation came while a callback was executing
0x00240005 WU_S_REBOOT_REQUIRED The system must be restarted to complete installation of the update
0x00240006 WU_S_ALREADY_INSTALLED The update to be installed is already installed on the system
0x00240007 WU_S_ALREADY_UNINSTALLED The update to be removed is not installed on the system
0x00240008 WU_S_ALREADY_DOWNLOADED The update to be downloaded has already been downloaded
"""

wsus_error_codes = """\
0x80240001 WU_E_NO_SERVICE Windows Update Agent was unable to provide the service.
0x80240002 WU_E_MAX_CAPACITY_REACHED The maximum capacity of the service was exceeded.
0x80240003 WU_E_UNKNOWN_ID An ID cannot be found.
0x80240004 WU_E_NOT_INITIALIZED The object could not be initialized.
0x80240005 WU_E_RANGEOVERLAP The update handler requested a byte range overlapping a previously requested range.
0x80240006 WU_E_TOOMANYRANGES The requested number of byte ranges exceeds the maximum number (2^31 - 1).
0x80240007 WU_E_INVALIDINDEX The index to a collection was invalid.
0x80240008 WU_E_ITEMNOTFOUND The key for the item queried could not be found.
0x80240009 WU_E_OPERATIONINPROGRESS Another conflicting operation was in progress. Some operations such as installation cannot be performed twice simultaneously.
0x8024000A WU_E_COULDNOTCANCEL Cancellation of the operation was not allowed.
0x8024000B WU_E_CALL_CANCELLED Operation was cancelled.
0x8024000C WU_E_NOOP No operation was required.
0x8024000D WU_E_XML_MISSINGDATA Windows Update Agent could not find required information in the update's XML data.
0x8024000E WU_E_XML_INVALID Windows Update Agent found invalid information in the update's XML data.
0x8024000F WU_E_CYCLE_DETECTED Circular update relationships were detected in the metadata.
0x80240010 WU_E_TOO_DEEP_RELATION Update relationships too deep to evaluate were evaluated.
0x80240011 WU_E_INVALID_RELATIONSHIP An invalid update relationship was detected.
0x80240012 WU_E_REG_VALUE_INVALID An invalid registry value was read.
0x80240013 WU_E_DUPLICATE_ITEM Operation tried to add a duplicate item to a list.
0x80240016 WU_E_INSTALL_NOT_ALLOWED Operation tried to install while another installation was in progress or the system was pending a mandatory restart.
0x80240017 WU_E_NOT_APPLICABLE Operation was not performed because there are no applicable updates.
0x80240018 WU_E_NO_USERTOKEN Operation failed because a required user token is missing.
0x80240019 WU_E_EXCLUSIVE_INSTALL_CONFLICT An exclusive update cannot be installed with other updates at the same time.
0x8024001A WU_E_POLICY_NOT_SET A policy value was not set.
0x8024001B WU_E_SELFUPDATE_IN_PROGRESS The operation could not be performed because the Windows Update Agent is self-updating.
0x8024001D WU_E_INVALID_UPDATE An update contains invalid metadata.
0x8024001E WU_E_SERVICE_STOP Operation did not complete because the service or system was being shut down.
0x8024001F WU_E_NO_CONNECTION Operation did not complete because the network connection was unavailable.
0x80240020 WU_E_NO_INTERACTIVE_USER Operation did not complete because there is no logged-on interactive user.
0x80240021 WU_E_TIME_OUT Operation did not complete because it timed out.
0x80240022 WU_E_ALL_UPDATES_FAILED Operation failed for all the updates.
0x80240023 WU_E_EULAS_DECLINED The license terms for all updates were declined.
0x80240024 WU_E_NO_UPDATE There are no updates.
0x80240025 WU_E_USER_ACCESS_DISABLED Group Policy settings prevented access to Windows Update.
0x80240026 WU_E_INVALID_UPDATE_TYPE The type of update is invalid.
0x80240027 WU_E_URL_TOO_LONG The URL exceeded the maximum length.
0x80240028 WU_E_UNINSTALL_NOT_ALLOWED The update could not be uninstalled because the request did not originate from a WSUS server.
0x80240029 WU_E_INVALID_PRODUCT_LICENSE Search may have missed some updates before there is an unlicensed application on the system.
0x8024002A WU_E_MISSING_HANDLER A component required to detect applicable updates was missing.
0x8024002B WU_E_LEGACYSERVER An operation did not complete because it requires a newer version of server.
0x8024002C WU_E_BIN_SOURCE_ABSENT A delta-compressed update could not be installed because it required the source.
0x8024002D WU_E_SOURCE_ABSENT A full-file update could not be installed because it required the source.
0x8024002E WU_E_WU_DISABLED Access to an unmanaged server is not allowed.
0x8024002F WU_E_CALL_CANCELLED_BY_POLICY Operation did not complete because the DisableWindowsUpdateAccess policy was set.
0x80240030 WU_E_INVALID_PROXY_SERVER The format of the proxy list was invalid.
0x80240031 WU_E_INVALID_FILE The file is in the wrong format.
0x80240032 WU_E_INVALID_CRITERIA The search criteria string was invalid.
0x80240033 WU_E_EULA_UNAVAILABLE License terms could not be downloaded.
0x80240034 WU_E_DOWNLOAD_FAILED Update failed to download.
0x80240035 WU_E_UPDATE_NOT_PROCESSED The update was not processed.
0x80240036 WU_E_INVALID_OPERATION The object's current state did not allow the operation.
0x80240037 WU_E_NOT_SUPPORTED The functionality for the operation is not supported.
0x80240038 WU_E_WINHTTP_INVALID_FILE The downloaded file has an unexpected content type.
0x80240039 WU_E_TOO_MANY_RESYNC Agent is asked by server to resync too many times.
0x80240040 WU_E_NO_SERVER_CORE_SUPPORT WUA API method does not run on Server Core installation.
0x80240041 WU_E_SYSPREP_IN_PROGRESS Service is not available while sysprep is running.
0x80240042 WU_E_UNKNOWN_SERVICE The update service is no longer registered with AU.
0x80240FFF WU_E_UNEXPECTED An operation failed due to reasons not covered by another error code.
"""