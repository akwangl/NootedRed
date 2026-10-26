// VDA / Hardware Video Decode Policy
//
// Copyright (C) 2026  ChefKiss.
//
// Licensed under the ChefKiss Open Knowledge License version 1.
//
// This work is licensed to you under the terms of the ChefKiss Open Knowledge
// License, either version 1 of the License, or (at your option) any later
// version published by ChefKiss.
//
// This work may not be used to train or develop artificial intelligence,
// and may not be used with artificial intelligence in any other way. See
// the ChefKiss Open Knowledge License for details.
//
// This work is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// ChefKiss Open Knowledge License for more details.
//
// You should have received a copy of the ChefKiss Open Knowledge License
// along with this work.  If not, see https://git.chefkiss.dev/ChefKiss/OpenKnowledge/raw/branch/master/LICENSE-v1.md.

#include <DeviceProfile.hpp>
#include <Headers/kern_util.hpp>
#include <NRed.hpp>
#include <VDA.hpp>
#include <libkern/OSTypes.h>

static VDA moduleInstance;

namespace
{

    const char* const kBootArgVDA = "-NRedVDA";
    const char* const kBootArgAVC = "-NRedAVC";
    const char* const kBootArgAVCEncode = "-NRedAVCEncode";
    const char* const kBootArgHEVC10 = "-NRedHEVC10";

}    // namespace

VDA& VDA::singleton() { return moduleInstance; }

void VDA::init()
{
    const bool vdaReq    = checkKernelArgument(kBootArgVDA);
    const bool avcReq    = checkKernelArgument(kBootArgAVC);
    const bool avcEncReq = checkKernelArgument(kBootArgAVCEncode);
    this->hevc10Allowed  = checkKernelArgument(kBootArgHEVC10);

    this->requested = vdaReq || avcReq || avcEncReq;
    this->avcOnly   = avcReq || avcEncReq;
    this->hevcEncodeAllowed = vdaReq || avcEncReq;

    if (!this->requested) {
        DBGLOG("VDA", "Hardware video decode is disabled; add -NRedVDA, -NRedAVC or -NRedAVCEncode to opt in (experimental)");
        return;
    }

    if (avcEncReq) {
        DBGLOG("VDA", "-NRedAVCEncode is set: Hardware AVC decode and HEVC encode enabled, HEVC decode disabled (software fallback)");
    }
    else if (this->avcOnly) {
        DBGLOG("VDA", "-NRedAVC is set: Hardware AVC/H.264 decode enabled, HEVC disabled (software fallback)");
    }
    else {
        if (this->hevc10Allowed) {
            DBGLOG("VDA", "-NRedVDA is set with -NRedHEVC10: hardware decode enabled for AVC and HEVC Main/Main 10");
        } else {
            DBGLOG("VDA", "-NRedVDA is set: hardware decode enabled for AVC and HEVC Main (8-bit); 10-bit HDR falls back to CPU");
        }
    }
}

void VDA::processPatcher()
{
    // Never null: DeviceProfile::current() falls back to the generic profile for unknown devices.
    const auto* const profile = DeviceProfile::current();

    const auto& media         = profile->media;
    const auto  vcnGeneration = static_cast<UInt32>(media.vcnGeneration);

    DBGLOG("VDA", "%s: VCN %u.%u, firmware %s, ring 0x%X, fence 0x%X, H.264=%u HEVC=%u AV1=%u", profile->name,
           vcnGeneration >> 8, vcnGeneration & 0xFF, media.vcnFirmware != nullptr ? media.vcnFirmware : "none",
           media.vcnRingSize, media.vcnFenceSize, static_cast<UInt32>(media.decode.h264),
           static_cast<UInt32>(this->avcOnly ? false : media.decode.hevc), static_cast<UInt32>(media.decode.av1));

    if (!this->requested) { return; }

    const char* modeName = "-NRedVDA";
    if (checkKernelArgument(kBootArgAVCEncode)) {
        modeName = "-NRedAVCEncode";
    } else if (this->avcOnly) {
        modeName = "-NRedAVC";
    }

    // The bridge reports its own readiness under the VCN tag; VDA only publishes the requested profile and
    // generation here.  If the bridge fails, software decode stays in use.
    DBGLOG("VDA", "%s requested for %s; VCN bridge readiness is reported by the VCN module",
           modeName, profile->name);

    NRed::singleton().setProp32("NRedVDARequested", static_cast<UInt32>(this->requested));
    NRed::singleton().setProp32("NRedVDAAVCOnly", static_cast<UInt32>(this->avcOnly));
    NRed::singleton().setProp32("NRedVDAHEVCEncodeAllowed", static_cast<UInt32>(this->hevcEncodeAllowed));
    NRed::singleton().setProp32("NRedVDAHEVC10Allowed", static_cast<UInt32>(this->hevc10Allowed));
    // The VCN bridge owns the effective enablement and updates this property after engine allocation.
    NRed::singleton().setProp32("NRedVDAMediaEnabled", 0);
    NRed::singleton().setProp32("NRedVCNGeneration", vcnGeneration);
}

