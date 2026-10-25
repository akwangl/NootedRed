// IOKit Personality Injector
//
// Copyright (C) 2025-2026  ChefKiss.
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

#include <DriverInjector.hpp>
#include <Headers/kern_patcher.hpp>
#include <Headers/kern_util.hpp>
#include <VDA.hpp>
#include <libkern/OSTypes.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSObject.h>
#include <libkern/c++/OSString.h>

static DriverInjector moduleInstance;

static const char com_apple_kext_AMDRadeonX5000[] = {
#include "Personalities/com.apple.kext.AMDRadeonX5000.inc"
, '\0'
};
static const char com_apple_kext_AMDRadeonX5000HWServices[] = {
#include "Personalities/com.apple.kext.AMDRadeonX5000HWServices.inc"
, '\0'
};
static const char com_apple_kext_AMDRadeonX6000Framebuffer[] = {
#include "Personalities/com.apple.kext.AMDRadeonX6000Framebuffer.inc"
, '\0'
};
static const char com_apple_driver_AppleGFXHDA[] = {
#include "Personalities/com.apple.driver.AppleGFXHDA.inc"
, '\0'
};

DriverInjector::DriverInjector() :
    drivers{
        Driver("com.apple.kext.AMDRadeonX6000Framebuffer", com_apple_kext_AMDRadeonX6000Framebuffer),
        Driver("com.apple.driver.AppleGFXHDA", com_apple_driver_AppleGFXHDA),
        Driver("com.apple.kext.AMDRadeonX5000", com_apple_kext_AMDRadeonX5000),
        Driver("com.apple.kext.AMDRadeonX5000HWServices", com_apple_kext_AMDRadeonX5000HWServices),
    }
{ }

DriverInjector& DriverInjector::singleton() { return moduleInstance; }

void DriverInjector::processPatcher(KernelPatcher& patcher)
{
    KernelPatcher::RouteRequest request{"__ZN11IOCatalogue10addDriversEP7OSArrayb", wrapAddDrivers,
                                        this->orgAddDrivers};
    PANIC_COND(!patcher.routeMultipleLong(KernelPatcher::KernelID, &request, 1), "DriverInjector",
               "Failed to route addDrivers");
}

bool DriverInjector::wrapAddDrivers(void* const self, OSArray* const array, const bool doNubMatching)
{
    UInt32 driverCount = array->getCount();
    for (UInt32 driverIndex = 0; driverIndex < driverCount; driverIndex += 1) {
        OSObject* object = array->getObject(driverIndex);
        if (object == nullptr) { continue; }
        auto* dict = OSDynamicCast(OSDictionary, object);
        if (dict == nullptr) { continue; }
        auto* bundleIdentifier = OSDynamicCast(OSString, dict->getObject("CFBundleIdentifier"));
        if (bundleIdentifier == nullptr || bundleIdentifier->getLength() == 0) { continue; }

        const auto toInjectCount = checkKernelArgument("-NRedNoAccel") ? 2 : arrsize(singleton().drivers);
        for (size_t identifierIndex = 0; identifierIndex < toInjectCount; identifierIndex += 1) {
            auto& driver = singleton().drivers[identifierIndex];

            if ((singleton().matchedDrivers & getBit(identifierIndex)) != 0
                || !bundleIdentifier->isEqualTo(driver.identifier))
            {
                continue;
            }

            singleton().matchedDrivers |= getBit(identifierIndex);

            DBGLOG("DriverInjector", "Matched %s, injecting.", driver.identifier);

            if (strcmp(driver.identifier, "com.apple.kext.AMDRadeonX5000") == 0) {
                const auto count = driver.personalities->getCount();
                if (VDA::singleton().isAVCOnly()) {
                    for (UInt32 i = 0; i < count; ++i) {
                        auto* const pDict = OSDynamicCast(OSDictionary, driver.personalities->getObject(i));
                        if (pDict != nullptr) {
                            pDict->removeObject("IOGVAHEVCDecode");
                            pDict->removeObject("IOGVAHEVCDecodeCapabilities");
                            if (!VDA::singleton().isHEVCEncodeAllowed()) {
                                pDict->removeObject("IOGVAHEVCEncode");
                                pDict->removeObject("IOGVAHEVCEncodeCapabilities");
                            }
                        }
                    }
                    if (VDA::singleton().isHEVCEncodeAllowed()) {
                        DBGLOG("DriverInjector", "-NRedAVCEncode active: stripped HEVC decode, preserved HEVC encode for %s", driver.identifier);
                    } else {
                        DBGLOG("DriverInjector", "-NRedAVC active: stripped HEVC decode/encode capabilities from %s", driver.identifier);
                    }
                }
                else if (!VDA::singleton().isHEVC10Allowed()) {
                    // Restrict HEVC hardware decode for Profile 2 (Main 10 / 10-bit HDR) by setting its
                    // VTMaxDecodeLevel to 0. When VideoToolbox checks the per-profile details, it sees
                    // VTMaxDecodeLevel = 0, determines that the hardware decoder cannot satisfy the video stream's level,
                    // and gracefully falls back to AppleSoftwareVideoDecoder (CPU software decoding).
                    // This prevents VCN 2.2 ASIC lockups while preserving hardware decode for standard 8-bit HEVC and H.264.
                    for (UInt32 i = 0; i < count; ++i) {
                        auto* const pDict = OSDynamicCast(OSDictionary, driver.personalities->getObject(i));
                        if (pDict == nullptr) { continue; }

                        auto* const hevcCaps = OSDynamicCast(OSDictionary, pDict->getObject("IOGVAHEVCDecodeCapabilities"));
                        if (hevcCaps == nullptr) { continue; }

                        auto* const details = OSDynamicCast(OSDictionary, hevcCaps->getObject("VTPerProfileDetails"));
                        if (details != nullptr) {
                            auto* const p2Dict = OSDynamicCast(OSDictionary, details->getObject("2"));
                            if (p2Dict != nullptr) {
                                auto* const zeroNum = OSNumber::withNumber(static_cast<unsigned long long>(0), 32);
                                if (zeroNum != nullptr) {
                                    p2Dict->setObject("VTMaxDecodeLevel", zeroNum);
                                    zeroNum->release();
                                }
                            }
                        }
                    }

                    auto* const hevcCapsInDict = OSDynamicCast(OSDictionary, dict->getObject("IOGVAHEVCDecodeCapabilities"));
                    if (hevcCapsInDict != nullptr) {
                        auto* const details = OSDynamicCast(OSDictionary, hevcCapsInDict->getObject("VTPerProfileDetails"));
                        if (details != nullptr) {
                            auto* const p2Dict = OSDynamicCast(OSDictionary, details->getObject("2"));
                            if (p2Dict != nullptr) {
                                auto* const zeroNum = OSNumber::withNumber(static_cast<unsigned long long>(0), 32);
                                if (zeroNum != nullptr) {
                                    p2Dict->setObject("VTMaxDecodeLevel", zeroNum);
                                    zeroNum->release();
                                }
                            }
                        }
                    }
                    DBGLOG("DriverInjector", "Protected HEVC decode: capped Profile 2 (Main 10) VTMaxDecodeLevel to 0 to guard against VCN2 hardware hang (pass -NRedHEVC10 to override)");
                }
            }

            array->merge(driver.personalities);

            break;
        }
    }

    return FunctionCast(wrapAddDrivers, singleton().orgAddDrivers)(self, array, doNubMatching);
}
