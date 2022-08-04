package cosmovisor

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hashicorp/go-getter"
	"github.com/otiai10/copy"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func (cfg *Config) UpgradeBinClient(upgradeName string) string {
	return filepath.Join(cfg.UpgradeDir(upgradeName), "bin", cfg.ClientName)
}

func (cfg *Config) GenesisBinClient() string {
	return filepath.Join(cfg.Root(), genesisDir, "bin", cfg.ClientName)
}

// Symlink to genesis
func (cfg *Config) SymLinkToGenesisClient() (string, error) {
	genesis := filepath.Join(cfg.Root(), genesisDir)
	link := filepath.Join(cfg.Root(), currentLink)

	if err := os.Symlink(genesis, link); err != nil {
		return "", err
	}
	// and return the genesis binary
	return cfg.GenesisBinClient(), nil
}

func (cfg *Config) CurrentBinClient() (string, error) {
	cur := filepath.Join(cfg.Root(), currentLink)
	// if nothing here, fallback to genesis
	// TODO Modify this to check zetaclient binary speficifically
	info, err := os.Lstat(cur)
	if err != nil {
		//Create symlink to the genesis
		return cfg.SymLinkToGenesisClient()
	}
	// if it is there, ensure it is a symlink
	if info.Mode()&os.ModeSymlink == 0 {
		//Create symlink to the genesis
		return cfg.SymLinkToGenesisClient()
	}

	// resolve it
	dest, err := os.Readlink(cur)
	if err != nil {
		//Create symlink to the genesis
		return cfg.SymLinkToGenesisClient()
	}

	// and return the binary
	return filepath.Join(dest, "bin", cfg.ClientName), nil
}

func (cfg *Config) AddClientConfig() {
	cfg.ClientName = os.Getenv("CLIENT_DAEMON_NAME")
	cfg.ClientArgs = os.Getenv("CLIENT_DAEMON_ARGS")
}

func (cfg *Config) validateClient() error {
	if cfg.ClientName == "" {
		return errors.New("CLIENT_DAEMON_NAME is not set")
	}
	if cfg.ClientArgs == "" {
		return errors.New("CLIENT_DAEMON_ARGS is not set")
	}
	return nil
}

func GetClientCMD(bin string, args []string) (*exec.Cmd, error) {
	cmd := exec.Command(bin, args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	return cmd, nil
}

func DownloadBinaryClient(cfg *Config, info *UpgradeInfo) error {
	url, err := GetDownloadURLClient(info, cfg)
	if err != nil {
		return err
	}
	// download into the bin dir (works for one file)
	binPath := cfg.UpgradeBinClient(info.Name)
	err = getter.GetFile(binPath, url)
	// if this fails, let's see if it is a zipped directory
	if err != nil {
		dirPath := cfg.UpgradeDir(info.Name)
		err = getter.Get(dirPath, url)
		if err != nil {
			return err
		}
		err = EnsureBinary(binPath)
		// copy binary to binPath from dirPath if zipped directory don't contain bin directory to wrap the binary
		if err != nil {
			err = copy.Copy(filepath.Join(dirPath, cfg.Name), binPath)
			if err != nil {
				return err
			}
		}
	}
	// if it is successful, let's ensure the binary is executable
	return MarkExecutable(binPath)
}

// GetDownloadURL will check if there is an arch-dependent binary specified in Info
func GetDownloadURLClient(info *UpgradeInfo, cfg *Config) (string, error) {
	doc := strings.TrimSpace(info.Info)
	// if this is a url, then we download that and try to get a new doc with the real info
	if _, err := url.Parse(doc); err == nil {
		tmpDir, err := ioutil.TempDir("", "upgrade-manager-reference")
		if err != nil {
			return "", fmt.Errorf("create tempdir for reference file: %w", err)
		}
		defer os.RemoveAll(tmpDir)

		refPath := filepath.Join(tmpDir, "ref")
		if err := getter.GetFile(refPath, doc); err != nil {
			return "", fmt.Errorf("downloading reference link %s: %w", doc, err)
		}

		refBytes, err := ioutil.ReadFile(refPath)
		if err != nil {
			return "", fmt.Errorf("reading downloaded reference: %w", err)
		}
		// if download worked properly, then we use this new file as the binary map to parse
		doc = string(refBytes)
	}

	// check if it is the upgrade config
	var config UpgradeConfig

	if err := json.Unmarshal([]byte(doc), &config); err == nil {
		os := OSArch()
		clientBinName := fmt.Sprintf("%s-%s", cfg.ClientName, os)
		clientBinNameAny := fmt.Sprintf("%s-%s", cfg.ClientName, "any")
		url, ok := config.Binaries[clientBinName]
		if !ok {
			url, ok = config.Binaries[clientBinNameAny]
		}
		if !ok {
			return "", fmt.Errorf("cannot find binary for os/arch: neither %s, nor any", OSArch())
		}
		return url, nil
	}
	return "", errors.New("upgrade info doesn't contain binary map")
}
