#!/usr/bin/env python3

# (C) 2025 Jack Lloyd
#
# Botan is released under the Simplified BSD License (see license.txt)

# This generates an initial pcurves implementation file, taking parameters
# from ec_named.txt
#
# This is useful for the (hopefully rare!) situation where someone needs fast
# curve-specific logic for an unusual or application specific curve.

from datetime import datetime
import os
import sys
import errno
from gen_ec_groups import curve_info
from addchain import addchain_code

def datestamp():
    current_date = datetime.now()
    return int(current_date.strftime("%Y%m%d"))

def find_params(name, curves):
    for curve in curves:
        if curve['Name'] == name:
            return curve

    raise Exception("Could not find curve named '%s' (do you need to update ec_groups.txt?)" % (name))

def main(args = None):
    if args is None:
        args = sys.argv

    if len(args) != 2:
        print("Usage: %s <curve_name>" % (args[0]))
        return 1

    curves = [c for c in curve_info(open('./src/build-data/ec_groups.txt'))]

    curve = args[1]
    curve_uc = curve.upper()
    curve_params = find_params(curve, curves)

    mod_dir = './src/lib/math/pcurves/pcurves_%s' % (curve)

    info_path = os.path.join(mod_dir, 'info.txt')

    try:
        os.makedirs(mod_dir)
    except OSError as ex:
        if ex.errno != errno.EEXIST:
            raise

    info_file = open(info_path, 'w')

    info_file.write("""<defines>
PCURVES_%s -> %d
</defines>

<module_info>
name -> "PCurve %s"
brief -> "%s"
</module_info>

<requires>
pcurves_impl
</requires>
""" % (curve_uc, datestamp(), curve, curve))
    info_file.close()

    src_file = open(os.path.join(mod_dir, 'pcurves_%s.cpp' % (curve)), 'w')

    # TODO if P is a Crandall number generate an appropriate Rep type

    indent = 9
    addchain_fe2 = addchain_code(curve_params['P'] - 2, indent)
    addchain_scalar = addchain_code(curve_params['N'], indent)

    src_file.write("""/*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pcurves_instance.h>

#include <botan/internal/pcurves_wrap.h>

namespace Botan::PCurve {

namespace {

namespace %s {

// clang-format off
class Params final : public EllipticCurveParameters<
   "%X",
   "%X",
   "%X",
   "%X",
   "%X",
   "%X"> {
};
// clang-format on

class Curve final : public EllipticCurve<Params> {
      // Return the square of the inverse of x
      static constexpr FieldElement fe_invert2(const FieldElement& x) {
         // Generated using https://github.com/mmcloughlin/addchain
%s
      }

      // Return the inverse of an integer modulo the order
      static constexpr Scalar scalar_invert(const Scalar& x) {
         // Generated using https://github.com/mmcloughlin/addchain
%s
      }

    };

}

}  // namespace

std::shared_ptr<const PrimeOrderCurve> PCurveInstance::%s() {
   return PrimeOrderCurveImpl<%s::Curve>::instance();
}

}  // namespace Botan::PCurve
""" % (curve, curve_params['P'], curve_params['A'], curve_params['B'], curve_params['N'], curve_params['X'], curve_params['Y'], addchain_fe2, addchain_scalar, curve, curve))

    src_file.close()
    return 0

if __name__ == '__main__':
    sys.exit(main())
