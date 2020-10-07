#!/usr/bin/env python3

from CompiledSEPolicy import SELinuxParser
import sys
import difflib


def main():
    pixelpolicy = SELinuxParser("./COMP/pixel/precompiled_sepolicy")
    pixelAVRules = pixelpolicy.getAllAVRules()

    hwpolicy = SELinuxParser("./COMP/huawei/precompiled_sepolicy")
    hwAVRules = hwpolicy.getAllAVRules()

    print("-= analysis result =-")
    print("Q1: who can access procfs:")
    for hwAVRule in hwAVRules:
        if hwAVRule[1] == "proc_security":
            print(hwAVRule)

    print("Q2: untrusted_app can access what:")
    for hwAVRule in hwAVRules:
        if hwAVRule[0] == "untrusted_app":
            print(hwAVRule)

    print("Q3: Compared with pixel, untrusted_app can access what:")
    pixelAVRuleCollection = []
    huaweiAVRuleCollection = []
    for pixelAVRule in pixelAVRules:
        if pixelAVRule[0] == "untrusted_app":
            pixelAVRuleCollection.append(pixelAVRule)

    for hwAVRule in hwAVRules:
        if hwAVRule[0] == "untrusted_app":
            huaweiAVRuleCollection.append(hwAVRule)


    diff_a_type = [(str(x)) for x in pixelAVRuleCollection]
    diff_b_type = [(str(x)) for x in huaweiAVRuleCollection]
    d = difflib.Differ()
    result = d.compare(diff_a_type, diff_b_type)
    add = list(filter(lambda x: x.startswith('+ '), result))
    print('\n'.join([item for item in add]))

    print("Q3: who can access surfaceflinger_tmpfs:")
    for hwAVRule in hwAVRules:
        if hwAVRule[1] == "surfaceflinger_tmpfs":
            print(hwAVRule)

    return

if __name__ == "__main__":
    sys.exit(main())
