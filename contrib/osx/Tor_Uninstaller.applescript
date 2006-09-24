-- Tor Uninstaller.applescript
-- Tor Uninstaller

-- ===============================================================================
-- Tor Uninstaller is distributed under this license:
--
-- Copyright (c) 2005 Andrew Lewman ( pgp key: 31B0974B )
-- 
-- Redistribution and use in source and binary forms, with or without
-- modification, are permitted provided that the following conditions are
-- met:
-- 
--     * Redistributions of source code must retain the above copyright
-- notice, this list of conditions and the following disclaimer.
-- 
--     * Redistributions in binary form must reproduce the above
-- copyright notice, this list of conditions and the following disclaimer
-- in the documentation and/or other materials provided with the
-- distribution.
-- 
--     * Neither the names of the copyright owners nor the names of its
-- contributors may be used to endorse or promote products derived from
-- this software without specific prior written permission.
-- 
-- THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
-- "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
-- LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
-- A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
-- OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
-- SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
-- LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
-- DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
-- THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
-- (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
-- OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-- ===============================================================================

-- Validate & find disk paths
set boot_disk to (path to startup disk) as string
set default_tor_path to boot_disk & "Library:Tor"
set default_privoxy_path to boot_disk & "Library:Privoxy"
set default_tor_startup_path to boot_disk & "Library:StartupItems:Tor"
set default_privoxy_startup_path to boot_disk & "Library:StartupItems:Privoxy"
set shell_script to default_tor_path & ":uninstall_tor_bundle.sh"
set doomed_path_list to {default_tor_path, default_privoxy_path, default_tor_startup_path, default_privoxy_startup_path}

-- Display what we're removing and ask for validation
-- this is the simplest way to do this
set remove_me to display dialog "Welcome to the Tor + Privoxy Uninstaller.  This program will remove:" & return & default_tor_path & return & default_privoxy_path & return & default_tor_startup_path & return & default_privoxy_startup_path & return & return & "If this does not look right, choose Yes.  Otherwise, choose No." buttons {"Yes", "No"} default button "No"

-- Run a shell script to do all the unix work since applescript can't see it at all
if button returned of result is "Yes" then
	try
		do shell script (shell_script) with administrator privileges
	on error
		display dialog "Too many errors, quitting." buttons {"Quit"} default button "Quit" with icon stop giving up after 5
		quit
	end try
	-- So Long and Thanks for all the Fish!
	display dialog "Thank you for using tor!" buttons {"Ok"} giving up after 5
else
	display dialog "Thank you for your continued use of Tor & Privoxy" buttons {"You're welcome."}
end if

-- We're done