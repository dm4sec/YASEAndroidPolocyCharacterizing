#!/usr/bin/env python3

from CompiledSEPolicy import SELinuxParser
import sys
import difflib


def main():
    hwpolicy = SELinuxParser("./COMP/huawei/precompiled_sepolicy")
    AVRulesLen, uselessAVRules, TERulesLen, uselessTERules = hwpolicy.getUselessRules()

    print("-= statistical result =-")
    print("%d useless AVRules (%f) found in huawei, which are listed below:" %(len(uselessAVRules), float(len(uselessAVRules))/AVRulesLen))
    print('\n'.join([str(item) for item in uselessAVRules]))
    print("%d useless TERules (%f) found in huawei, which are listed below:" %(len(uselessTERules), float(len(uselessTERules))/TERulesLen))
    print('\n'.join([str(item) for item in uselessTERules]))

    return

if __name__ == "__main__":
    sys.exit(main())
