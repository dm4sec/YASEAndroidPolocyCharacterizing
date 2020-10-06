#!/usr/bin/env python3

from CompiledSEPolicy import SELinuxParser
import sys
import difflib


def main():
    pixelpolicy = SELinuxParser("./COMP/pixel/precompiled_sepolicy")
    hwpolicy = SELinuxParser("./COMP/huawei/precompiled_sepolicy")

    pixelpolicySubject = []
    hwpolicySubject = []

    for sub in ["system_app", "platform_app"]:
        pixelpolicySubject += pixelpolicy.getSubAllow(sub)
        hwpolicySubject += hwpolicy.getSubAllow(sub)

    diff_a_type = [(str(x)) for x in pixelpolicySubject]
    diff_b_type = [(str(x)) for x in hwpolicySubject]
    d = difflib.Differ()

    result = d.compare(diff_a_type, diff_b_type)
    remove = list(filter(lambda x: x.startswith('- '), result))
    # ugly coding
    result = d.compare(diff_a_type, diff_b_type)
    add = list(filter(lambda x: x.startswith('+ '), result))

    print("-= statistical result =-")
    print("%d rules in pixel use predefined domain" %(len(diff_a_type)))
    print("%d rules in huawei use predefined domain" %(len(diff_b_type)))
    print("huawei removed %d rules in comparison with pixel, which are listed below:" %(len(remove)))
    print('\n'.join([item for item in remove]))
    print("huawei added %d rules in comparison with pixel, which are listed below:" %(len(add)))
    print('\n'.join([item for item in add]))

    return

if __name__ == "__main__":
    sys.exit(main())
