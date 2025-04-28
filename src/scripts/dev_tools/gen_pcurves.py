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
from textwrap import dedent,indent
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

class OmitFirstLine:
    def __init__(self):
        self.first_line = True

    def __call__(self, l):
        r = not self.first_line
        self.first_line = False
        return r

def main(args = None):
    if args is None:
        args = sys.argv

    if len(args) != 2:
        print("Usage: %s <curve_name>" % (args[0]))
        return 1

    with open('./src/build-data/ec_groups.txt', encoding='utf8') as ec_groups:
        curves = list(curve_info(ec_groups))

    curve = args[1]
    curve_params = find_params(curve, curves)

    mod_dir = './src/lib/math/pcurves/pcurves_%s' % (curve)
    info_path = os.path.join(mod_dir, 'info.txt')
    impl_path = os.path.join(mod_dir, f'pcurves_{curve}.cpp')

    try:
        os.makedirs(mod_dir)
    except OSError as ex:
        if ex.errno != errno.EEXIST:
            raise

    with open(info_path, 'w', encoding='utf8') as info_file:
        info_file.write(dedent(f"""\
            <defines>
            PCURVES_{curve.upper()} -> {datestamp()}
            </defines>

            <module_info>
            name -> "PCurve {curve}"
            </module_info>

            <requires>
            pcurves_impl
            </requires>
            """))

    with open(impl_path, 'w', encoding='utf8') as src_file:
        # TODO if P is a Crandall number generate an appropriate Rep type

        addchain_fe2 = addchain_code(curve_params['P'] - 2, 0)
        addchain_scalar = addchain_code(curve_params['N'], 0)

        src_file.write(dedent(f"""\
            /*
            * Botan is released under the Simplified BSD License (see license.txt)
            */

            #include <botan/internal/pcurves_instance.h>

            #include <botan/internal/pcurves_wrap.h>

            namespace Botan::PCurve {{

            namespace {{

            namespace {curve} {{

            // clang-format off
            class Params final : public EllipticCurveParameters<
               "{curve_params['P']:X}",
               "{curve_params['A']:X}",
               "{curve_params['B']:X}",
               "{curve_params['N']:X}",
               "{curve_params['X']:X}",
               "{curve_params['Y']:X}"> {{
            }};
            // clang-format on

            class Curve final : public EllipticCurve<Params> {{
               // Return the square of the inverse of x
               static constexpr FieldElement fe_invert2(const FieldElement& x) {{
                  // Generated using https://github.com/mmcloughlin/addchain
                  {indent(addchain_fe2, 18 * ' ', OmitFirstLine())}
               }}

               // Return the inverse of an integer modulo the order
               static constexpr Scalar scalar_invert(const Scalar& x) {{
                  // Generated using https://github.com/mmcloughlin/addchain
                  {indent(addchain_scalar, 18 * ' ', OmitFirstLine())}
               }}
            }};

            }}  // namespace {curve}

            }}  // namespace

            std::shared_ptr<const PrimeOrderCurve> PCurveInstance::{curve}() {{
               return PrimeOrderCurveImpl<{curve}::Curve>::instance();
            }}

            }}  // namespace Botan::PCurve
            """))

    return 0

if __name__ == '__main__':
    sys.exit(main())
