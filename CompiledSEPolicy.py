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
