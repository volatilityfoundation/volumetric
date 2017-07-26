import volumetric
from volumetric import server

if __name__ == "__main__":
    parser = server.VolumetricServer.get_argument_parser()
    args = parser.parse_args()

    vs = volumetric.server.VolumetricServer(args)
    vs.run()
