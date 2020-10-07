import setools

from setools.policyrep import terule
from setools.policyrep import exception

class SELinuxParser(setools.SELinuxPolicy):
    """Overloaded SELinuxPolicy"""
    def getType(self, ty):
        retMe = []

        sort = True

        def cond_sort(value):
            """Helper function to sort values according to the sort parameter"""
            return value if not sort else sorted(value)

        for type_ in cond_sort(self.types()):
            name = str(type_)
            if name == ty:
                for alias in type_.aliases():
                    print("[e] alias of type found.")

        #subject object class perms
        for terule_ in cond_sort(self.terules()):
            # allowxperm rules
            if isinstance(terule_, terule.AVRuleXperm):
                # "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.xperm_type}"
                pass
            # allow/dontaudit/auditallow/neverallow rules
            elif isinstance(terule_, terule.AVRule):
                # "{0.ruletype} {0.source} {0.target}:{0.tclass}"
                if str(terule_.source) == ty or str(terule_.target) == ty:
                    retMe.append(["AVRule", str(terule_.source).strip(), str(terule_.target).strip(), str(terule_.tclass).strip(), [str(x).strip() for x in terule_.perms]])
            # type_* type enforcement rules
            elif isinstance(terule_, terule.TERule):
                # "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.default}".format(terule_)
                if str(terule_.source) == ty or str(terule_.default) == ty or str(terule_.target) == ty :
                   retMe.append(["TERule", str(terule_.source).strip(), str(terule_.default).strip(), str(terule_.tclass).strip(), str(terule_.target).strip()])
            else:
                raise RuntimeError("Unhandled TE rule")

        return retMe

    # subject (direct), attribute (indirect), alias are collected
    def getSubAllow(self, sub):
        retMe = []

        sort = True

        def cond_sort(value):
            """Helper function to sort values according to the sort parameter"""
            return value if not sort else sorted(value)

        # base identifiers
        attributes = {}
        types = {}
        aliases = {}
        sub_collection = []

        # define type attributes
        for attribute_ in cond_sort(self.typeattributes()):
            attributes[str(attribute_)] = []

        # define types, aliases and attributes
        for type_ in cond_sort(self.types()):
            name = str(type_)

            for attr in type_.attributes():
                attributes[str(attr)] += [name]

            for alias in type_.aliases():
                types[str(alias)] = name
                aliases[str(alias)] = True

            types[name] = [str(x) for x in type_.attributes()]

        sub_collection = types[sub] + [sub]
        for a in types.keys():
            if types[a] == sub:
                sub_collection += [a]

        #subject object class perms
        for terule_ in cond_sort(self.terules()):
            # allowxperm rules
            if isinstance(terule_, terule.AVRuleXperm):
                # "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.xperm_type}"
                pass
            # allow/dontaudit/auditallow/neverallow rules
            elif isinstance(terule_, terule.AVRule):
                # "{0.ruletype} {0.source} {0.target}:{0.tclass}"
                if str(terule_.source) in sub_collection:
                    retMe.append(["AVRule", str(terule_.source).strip(), str(terule_.target).strip(), str(terule_.tclass).strip(), [str(x).strip() for x in terule_.perms]])
            # type_* type enforcement rules
            elif isinstance(terule_, terule.TERule):
                # "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.default}".format(terule_)
                if str(terule_.source) in sub_collection:
                   retMe.append(["TERule", str(terule_.source).strip(), str(terule_.default).strip(), str(terule_.tclass).strip(), str(terule_.target).strip()])
            else:
                raise RuntimeError("Unhandled TE rule")

        return retMe

    # check
    # https://android.googlesource.com/platform/system/sepolicy/+/refs/heads/android10-c2f2-release/public/te_macros
    # and https://android.googlesource.com/platform/system/sepolicy/+/refs/heads/android10-c2f2-release/public/global_macros
    # to find how this works.
    # TODO:: boring, I have gave up
    def getUselessRules(self):
        AVRules = []
        TERules = []

        uselessAVRules = []
        uselessTERules = []

        sort = True

        def cond_sort(value):
            """Helper function to sort values according to the sort parameter"""
            return value if not sort else sorted(value)

        #subject object class perms
        for terule_ in cond_sort(self.terules()):
            # allowxperm rules
            if isinstance(terule_, terule.AVRuleXperm):
                # "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.xperm_type}"
                pass
            # allow/dontaudit/auditallow/neverallow rules
            elif isinstance(terule_, terule.AVRule):
                # "{0.ruletype} {0.source} {0.target}:{0.tclass}"
                if terule_.ruletype == "allow" or terule_.ruletype == "auditallow":
                    AVRules.append([str(terule_.source), str(terule_.target), str(terule_.tclass), terule_.perms])
                elif terule_.ruletype == "dontaudit":
                    pass
                else:
                    print("Unhandled AVRule: %s" %(str(terule_.ruletype)))
            # type_* type enforcement rules
            elif isinstance(terule_, terule.TERule):
                # "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.default}".format(terule_)
                if terule_.ruletype == "type_transition":
                    TERules.append([str(terule_.source), str(terule_.target), str(terule_.tclass), str(terule_.default)])
                else:
                    print("Unhandled TERule: %s" %(str(terule_.ruletype)))

            else:
                raise RuntimeError("Unhandled TE rule")

        checkinRule = []
        for teRule in TERules:
            # domain_trans
            if teRule[2] == "process":
                b_execute = False
                b_transition = False
                b_entrypoint = False
                for avRule in AVRules:
                    # {"getattr", "open", "read", "execute", "map"}
                    if avRule[0] == teRule[0] and avRule[1] == teRule[1] and avRule[2] == "file" and "execute" in avRule[3]:
                        b_execute = True
                        checkinRule.append(avRule)
                    if avRule[0] == teRule[0] and avRule[1] == teRule[3] and avRule[2] == "process" and "transition" in avRule[3]:
                        checkinRule.append(avRule)
                        b_transition = True
                    if avRule[0] == teRule[3] and avRule[1] == teRule[1] and avRule[2] == "file" and "entrypoint" in avRule[3]:
                        checkinRule.append(avRule)
                        b_entrypoint = True
                if b_execute and b_transition and b_entrypoint:
                    pass
                else:
                    uselessTERules.append(teRule)
            #file_type_trans
            #{"file", "lnk_file", "sock_file", "fifo_file"}
            elif "fifo_file" == teRule[2]:
                b_file = False
                b_lnk_file = False
                b_sock_file = False
                for subTERule in TERules:
                    if subTERule[0] == teRule[0] and subTERule[1] == teRule[1] and subTERule == "file" and subTERule[3] == teRule[3]:
                        b_file = True
                    if subTERule[0] == teRule[0] and subTERule[1] == teRule[1] and subTERule == "lnk_file" and subTERule[3] == teRule[3]:
                        b_lnk_file = True
                    if subTERule[0] == teRule[0] and subTERule[1] == teRule[1] and subTERule == "sock_file" and subTERule[3] == teRule[3]:
                        b_sock_file = True
                if b_file and b_lnk_file and b_sock_file:
                    pass
                else:
                    uselessTERules.append(teRule)
        # cross check AVRule for domain_trans
        for avRule in AVRules:
            if avRule[2] == "file" and "execute" in avRule[3] and avRule not in checkinRule:
                uselessAVRules.append(avRule)
            if avRule[2] == "process" and "transition" in avRule[3] and avRule not in checkinRule:
                uselessAVRules.append(avRule)
            if avRule[2] == "file" and "entrypoint" in avRule[3] and avRule not in checkinRule:
                uselessAVRules.append(avRule)

        return len(AVRules), uselessAVRules, len(TERules), uselessTERules

    # analysis in user's code
    def getAllAVRules(self):
        sort = True

        AVRules = []
        def cond_sort(value):
            """Helper function to sort values according to the sort parameter"""
            return value if not sort else sorted(value)

        #subject object class perms
        for terule_ in cond_sort(self.terules()):
            # allowxperm rules
            if isinstance(terule_, terule.AVRuleXperm):
                # "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.xperm_type}"
                pass
            # allow/dontaudit/auditallow/neverallow rules
            elif isinstance(terule_, terule.AVRule):
                # "{0.ruletype} {0.source} {0.target}:{0.tclass}"
                if terule_.ruletype == "allow" or terule_.ruletype == "auditallow":
                    AVRules.append([str(terule_.source), str(terule_.target), str(terule_.tclass), terule_.perms])
                elif terule_.ruletype == "dontaudit":
                    pass
                else:
                    print("Unhandled AVRule: %s" %(str(terule_.ruletype)))
            # type_* type enforcement rules
            elif isinstance(terule_, terule.TERule):
                pass
            else:
                raise RuntimeError("Unhandled TE rule")

        return AVRules
