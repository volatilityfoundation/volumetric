# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#


import volumetric
from volumetric import server

if __name__ == "__main__":
    parser = server.VolumetricServer.get_argument_parser()
    args = parser.parse_args()

    vs = volumetric.server.VolumetricServer(args)
    vs.run()
