#!/usr/bin/env python3

from CompiledSEPolicy import SELinuxParser
import sys
import difflib


def main():
    pixelpolicy = SELinuxParser("./COMP/pixel/precompiled_sepolicy")
    hwpolicy = SELinuxParser("./COMP/huawei/precompiled_sepolicy")

    pixelpolicyType = []
    hwpolicyType = []

    for ty in ["unlabeled", "device", "socket_device", "default_prop", "system_data_file"]:
        pixelpolicyType += pixelpolicy.getType(ty)
        hwpolicyType += hwpolicy.getType(ty)

    diff_a_type = ""
    diff_b_type = ""


    diff_a_type = [(str(x) + "\n") for x in pixelpolicyType]
    diff_b_type = [(str(x) + "\n") for x in hwpolicyType]

    result = difflib.Differ().compare(diff_a_type, diff_b_type)

    remove = list(filter(lambda x: x.startswith('- '), result))
    add = list(filter(lambda x: x.startswith('+ '), result))

    print("-= statistical result =-")
    print("%d rules in pixel use default type" %(len(diff_a_type)))
    print("%d rules in huawei use default type" %(len(diff_b_type)))
    print("huawei removed %d rules in comparison with pixel, which are listed below:" %(len(remove)))
    print(remove)
    print("huawei added %d rules in comparison with pixel, which are listed below:" %(len(add)))
    print(add)

    return

if __name__ == "__main__":
    sys.exit(main())
