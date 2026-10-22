-- AppleForge
--
-- Copyright (C) 2026  ChefKiss
--
-- Licensed under the ChefKiss Open Knowledge License version 1.
--
-- This work is licensed to you under the terms of the ChefKiss Open Knowledge
-- License, either version 1 of the License, or (at your option) any later
-- version published by ChefKiss.
--
-- This work may not be used to train or develop artificial intelligence,
-- and may not be used with artificial intelligence in any other way. See
-- the ChefKiss Open Knowledge License for details.
--
-- This work is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- ChefKiss Open Knowledge License for more details.
--
-- You should have received a copy of the ChefKiss Open Knowledge License
-- along with this work.  If not, see https://git.chefkiss.dev/ChefKiss/OpenKnowledge/raw/branch/master/LICENSE-v1.md.

function AppleForge_ApplyDefaults()
	set_defaultplat("macosx")
	set_allowedplats("macosx")

	set_allowedmodes("debug", "release", "releasedbg")
	set_allowedarchs("i386", "x86_64", "arm64")

	set_policy("build.progress_style", "multirow")

	set_symbols("hidden", "debug")
	if is_mode("debug") then
		set_optimize("none")
	else
		set_optimize("fastest")
		add_cxflags("-fdata-sections", "-ffunction-sections", "-fmerge-all-constants")
		add_ldflags("-Wl,-dead_strip")
	end
	if not is_mode("release") then
		add_defines("DEBUG=1", "APPLE_KEXT_ASSERTIONS=1", "MACH_ASSERT=1")
	end
	add_cxflags(
		"-fdiagnostics-show-note-include-stack",
		"-ftrivial-auto-var-init=zero",
		"-fasm-blocks",
		"-Wall",
		"-Wextra",
		"-Wpedantic",
		"-Wshadow",
		"-Wconversion",
		"-Wsign-conversion",
		"-Wdouble-promotion",
		"-Wcast-align",
		"-Wcast-qual",
		"-Wformat=2",
		"-Wundef",
		"-Wnull-dereference",
		"-Wimplicit-fallthrough",
		"-Wunreachable-code",
		"-Wmissing-field-initializers",
		"-Woverloaded-virtual",
		"-Wnon-virtual-dtor",
		-- "-Wold-style-cast",
		-- "-Wreserved-id-macro",
		"-Wdocumentation",
		"-Wdelete-non-virtual-dtor",
		"-Wsuggest-override",
		"-Wweak-vtables",
		"-Wthread-safety",
		"-Wframe-larger-than=1024",
		"-Wuninitialized",
		"-Wconditional-uninitialized",
		"-Wno-extra-semi",
		"-Wno-c99-extensions",
		"-Wno-gnu-anonymous-struct",
		"-Wno-gnu-statement-expression",
		"-Wno-deprecated",
		"-Wno-format-nonliteral",
		"-Wno-gnu-zero-variadic-macro-arguments"
		-- "-Werror"
	)
end

local function macos_ver_to_define(ver)
	local parts = {}
	for p in ver:gmatch("%d+") do
		table.insert(parts, tonumber(p))
	end
	local major, minor = parts[1] or 0, parts[2] or 0
	local patch = parts[3] or 0
	-- 10.0-10.9 use the 4-digit legacy encoding (e.g. 10.9 → 1090)
	if major == 10 and minor < 10 then
		return 1000 + minor * 10
	end
	return major * 10000 + minor * 100 + patch
end

local function kmod_info_source(bundleid, version, start_fn, stop_fn)
	local extern_start_fn, extern_stop_fn = "", ""
	if start_fn then
		extern_start_fn = [[__private_extern__ kern_return_t ]] .. start_fn .. [[(kmod_info_t *ki, void *d);]] .. "\n"
	end
	if stop_fn then
		extern_stop_fn = [[__private_extern__ kern_return_t ]] .. stop_fn .. [[(kmod_info_t *ki, void *d);]] .. "\n"
	end

	return string.format(
		[[
#include <libkern/libkern.h>
#include <mach/mach_types.h>
#include <mach/kmod.h>
%s%s%s
__private_extern__ kern_return_t _start(kmod_info_t *ki, void *d);
__private_extern__ kern_return_t _stop(kmod_info_t *ki, void *d);

__attribute__((visibility("default")))
KMOD_EXPLICIT_DECL(%s, "%s", _start, _stop)

__private_extern__ kmod_start_func_t *_realmain = %s;
__private_extern__ kmod_stop_func_t *_antimain = %s;
__private_extern__ int _kext_apple_cc = __APPLE_CC__;
]],
		(start_fn or stop_fn) and "\n" or "",
		extern_start_fn,
		extern_stop_fn,
		bundleid,
		version,
		start_fn or "NULL",
		stop_fn or "NULL"
	)
end

local function render_plist(io, src, dst, vars)
	local text = io.readfile(src)
	local function replval(k)
		return vars[k] or raise("Undefined constant " .. k)
	end
	text = text:gsub("%$%(([%w_:]+)%)", replval)
	text = text:gsub("%${([%w_:]+)}", replval)
	io.writefile(dst, text)
end

local function using_apple_clang(os, target)
	local cc = target:tool("cc")
	if not cc then
		return false
	end
	local output, _ = os.iorunv(cc, { "--version" })
	return output and output:find("Apple clang", 1, true)
end

local function target_product_name(target)
	return target:values("ProductName") or target:name()
end

local function build_mode()
	return string.upper(get_config("mode") or "release")
end

local function zip_filename(name, ver)
	return string.format("%s-%s-%s.zip", name, ver, build_mode())
end

local function kext_bundle_path(target, name)
	return path.join(target:targetdir(), name .. ".kext")
end

local function require_submodule(name, label, dir, forgedir)
	if not dir or not os.isdir(dir) then
		if not name then
			raise(
				"${green}[AppleForge]: Missing %s!\n"
					.. " ${yellow}hint:${clear} `git submodule update --init` in AppleForge's folder (%s)\n",
				label,
				forgedir
			)
		end
		raise(
			"${green}[AppleForge]: ${magenta}<%s>${clear} Missing %s!\n"
				.. " ${yellow}hint:${clear} `git submodule update --init` in AppleForge's folder (%s)\n",
			name,
			label,
			forgedir
		)
	end
end

local function value_or_warn(cprint, target, key, label)
	local val = target:values(key)
	if val and val ~= "" then
		return val
	end
	cprint(
		"${yellow}warning: ${green}[AppleForge]: ${magenta}<%s>${clear} No %s specified.${clear}",
		target:name(),
		label
	)
	return nil
end

local forgedir = path.normalize(path.join(os.scriptdir(), "../.."))
local sdk = path.join(forgedir, "MacKernelSDK")

require_submodule(nil, "MacKernelSDK", sdk, forgedir)

rule("AppleKext")
	on_load(function(target)
		target:set("toolchains", "clang")
		target:set("policy", "check.auto_ignore_flags", false)
		local gen_file = path.join(target:autogendir(), "KModInfo.c")
		if not os.isfile(gen_file) then
			io.writefile(gen_file, "#error placeholder\n")
		end
		target:add("files", gen_file)
		if (get_config("arch") or os.arch()) == "i386" then
			target:add(
				"files",
				path.join(sdk, "Library/kmod/i386_builtins.c"),
				path.join(sdk, "Library/kmod/cplus_start.c"),
				path.join(sdk, "Library/kmod/cplus_stop.c")
			)
		else
			target:add("files", path.join(sdk, "Library/kmod/c_start.c"), path.join(sdk, "Library/kmod/c_stop.c"))
		end
	end)

	on_config(function(target)
		local name = target:name()
		local product_name = target_product_name(target)

		local min_os = target:values("DeploymentTarget") or "11.0"

		local arch = get_config("arch") or os.arch()
		local arch_cxflags, arch_ldflags
		if arch == "x86_64" then
			arch_cxflags = {
				"-mno-red-zone",
				"-mmmx",
				"-msse",
				"-msse2",
				"-msse3",
				"-mfpmath=sse",
				"-mssse3",
			}
			arch_ldflags = {}
		else
			arch_cxflags = { "-mstrict-align" }
			arch_ldflags = { "-fixup-chains" }
		end

		local target_flag = "--target=" .. arch .. "-apple-macos" .. min_os
		local common = {
			target_flag,
			"-nostdinc",
			"-fno-builtin",
			"-fno-exceptions",
			"-fno-sanitize=vptr",
			"-fno-rtti",
			"-fno-common",
			"-fno-non-call-exceptions",
			"-fno-asynchronous-unwind-tables",
		}
		for _, f in ipairs(arch_cxflags) do
			table.insert(common, f)
		end

		local is_apple_clang = using_apple_clang(os, target)
		if not is_mode("debug") then
			target:set("strip", "all")
		end
		target:add("cxflags", table.unpack(common))
		target:add("cxxflags", "-fapple-kext")
		target:add("mxxflags", "-fapple-kext")
		target:add("ldflags", table.unpack(common))
		target:add("ldflags", table.unpack(arch_ldflags))

		target:add("ldflags", "-fapple-kext", "-static", "-nostdlib", "-nostdlib++")

		if is_apple_clang then
			target:add("ldflags", "-Wl,-kext")
		else
			target:add("ldflags", "-fuse-ld=lld")
			if not is_mode("debug") then
				target:add("ldflags", "-Wl,--icf=all")
			end
		end

		local os_ver_num = macos_ver_to_define(min_os)
		local ver = target:version()
		target:add(
			"defines",
			"KERNEL",
			"KERNEL_PRIVATE",
			"DRIVER_PRIVATE",
			"APPLE",
			"NeXT",
			string.format("MAC_OS_X_VERSION_MIN_REQUIRED=%d", os_ver_num),
			string.format("__MAC_OS_X_VERSION_MIN_REQUIRED=%d", os_ver_num),
			"MODULE_VERSION=" .. ver,
			"PRODUCT_NAME=" .. product_name
		)

		target:add("sysincludedirs", path.join(sdk, "Headers"))

		local bundle_identifier = target:values("BundleIdentifier")
		assert(bundle_identifier, "${green}[AppleForge]: ${magenta}<%s>${clear} No bundle identifier specified.", name)
		assert(ver, "${green}[AppleForge] ${magenta}<%s>${clear} No bundle version specified.", name)
		local kmod_entry = value_or_warn(cprint, target, "ModuleEntryPoint", "module entry point")
		local kmod_exit = value_or_warn(cprint, target, "ModuleExitPoint", "module exit point")
		io.writefile(
			path.join(target:autogendir(), "KModInfo.c"),
			kmod_info_source(bundle_identifier, ver, kmod_entry, kmod_exit)
		)

		target:add("linkdirs", path.join(sdk, "Library", "universal"))
		target:add("links", "kmod", "kmodc++")
	end)
	after_build(function(target)
		import("utils.archive")

		local name = target:name()
		local product_name = target_product_name(target)
		local kext_dir = kext_bundle_path(target, name)
		local contents_dir = path.join(kext_dir, "Contents")
		local macos_dir = path.join(contents_dir, "MacOS")

		if not is_mode("debug") then
			local strip = target:tool("strip")
			if strip then
				os.vrunv(strip, { "-x", target:targetfile() })
			end
		end

		os.tryrm(kext_dir)
		os.mkdir(macos_dir)
		os.mv(target:targetfile(), path.join(macos_dir, name))
		local license = path.join(target:scriptdir(), "LICENSE")
		if not os.exists(license) then
			license = path.join(target:scriptdir(), "LICENSE.md")
		end
		if os.exists(license) then
			os.cp(license, target:targetdir())
		end

		local plist_path = path.join(target:scriptdir(), name, "Info.plist")
		assert(
			plist_path and os.isfile(plist_path),
			"${green}[AppleForge]: ${magenta}<%s>${clear} Missing Info.plist!",
			name
		)

		local ver = target:version()
		render_plist(io, plist_path, path.join(contents_dir, "Info.plist"), {
			PRODUCT_NAME = product_name,
			["PRODUCT_NAME:rfc1034identifier"] = product_name,
			EXECUTABLE_NAME = name,
			PRODUCT_BUNDLE_IDENTIFIER = target:values("BundleIdentifier"),
			MODULE_VERSION = ver,
			MARKETING_VERSION = ver,
			CURRENT_PROJECT_VERSION = target:values("Build") or ver,
		})

		cprint("${green}[AppleForge]:${clear} ${magenta}<%s>${clear} Kext generated successfully (%s)", name, kext_dir)

		local zip_name = zip_filename(name, ver)
		local zip_path = path.join(target:targetdir(), zip_name)
		os.tryrm(zip_path)
		archive.archive(
			zip_name,
			".",
			{ curdir = target:targetdir(), recurse = true, compress = "best", excludes = { ".*", "*.zip" } }
		)
		cprint("${green}[AppleForge]:${clear} ${magenta}<%s>${clear} Kext zip generated successfully (%s)", name, zip_path)
	end)
	after_clean(function(target)
		local name = target:name()
		local ver = target:version()
		os.tryrm(kext_bundle_path(target, name))
		os.tryrm(path.join(target:targetdir(), zip_filename(name, ver)))
	end)
rule_end()

rule("LiluPlugIn")
	add_deps("AppleKext")
	on_load(function(target)
		local name = target:name()
		local product_name = target_product_name(target)
		local lilu = path.join(forgedir, "Lilu")

		require_submodule(name, "Lilu", lilu, forgedir)

		target:add("sysincludedirs", path.join(lilu, "Lilu"))
		target:add("files", path.join(lilu, "Lilu/Library/plugin_start.cpp"))
		target:set("values", "ModuleEntryPoint", product_name .. "_kern_start")
		target:set("values", "ModuleExitPoint", product_name .. "_kern_stop")
	end)
rule_end()
