import logging, os, sys

def init_logger(outdir, name="penai"):
    os.makedirs(outdir, exist_ok=True)
    logpath = f"{outdir}/logs/agent.log"
    fh = logging.FileHandler(logpath)
    sh = logging.StreamHandler(sys.stdout)
    fmt = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    fh.setFormatter(fmt)
    sh.setFormatter(fmt)
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    # prevent duplicate handlers
    if not any(isinstance(h, logging.FileHandler) and h.baseFilename==os.path.abspath(logpath) for h in logger.handlers):
        logger.addHandler(fh)
        logger.addHandler(sh)
    return logger
