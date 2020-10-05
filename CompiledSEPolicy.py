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