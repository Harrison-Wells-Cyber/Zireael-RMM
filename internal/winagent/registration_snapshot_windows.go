package winagent

import (
	"errors"
	"golang.org/x/sys/windows/registry"
)

// Capture only fields this program owns; unrelated values are never rewritten.
func snapshotRegistration(dir, mode string) (func() error, error) {
	hive, path := uninstallRegistry(dir, mode)
	key, e := registry.OpenKey(hive, path, registry.QUERY_VALUE)
	if errors.Is(e, registry.ErrNotExist) {
		return func() error { return removeUninstallEntry(dir, mode) }, nil
	}
	if e != nil {
		return nil, e
	}
	defer key.Close()
	owned, e := ownsUninstallKey(key, dir)
	if e != nil {
		return nil, e
	}
	if !owned {
		return nil, errors.New("another installation owns the uninstall registration")
	}
	strings := map[string]*string{}
	numbers := map[string]*uint32{}
	for _, name := range []string{"DisplayName", "Publisher", "DisplayVersion", "DisplayIcon", "InstallLocation", "UninstallString"} {
		value, _, err := key.GetStringValue(name)
		if errors.Is(err, registry.ErrNotExist) {
			strings[name] = nil
		} else if err != nil {
			return nil, err
		} else {
			v := value
			strings[name] = &v
		}
	}
	for _, name := range []string{"NoModify", "NoRepair"} {
		value, _, err := key.GetIntegerValue(name)
		if errors.Is(err, registry.ErrNotExist) {
			numbers[name] = nil
		} else if err != nil {
			return nil, err
		} else {
			v := uint32(value)
			numbers[name] = &v
		}
	}
	return func() error {
		k, _, err := registry.CreateKey(hive, path, registry.QUERY_VALUE|registry.SET_VALUE)
		if err != nil {
			return err
		}
		defer k.Close()
		for name, value := range strings {
			if value == nil {
				err = k.DeleteValue(name)
			} else {
				err = k.SetStringValue(name, *value)
			}
			if err != nil && !errors.Is(err, registry.ErrNotExist) {
				return err
			}
		}
		for name, value := range numbers {
			if value == nil {
				err = k.DeleteValue(name)
			} else {
				err = k.SetDWordValue(name, *value)
			}
			if err != nil && !errors.Is(err, registry.ErrNotExist) {
				return err
			}
		}
		return nil
	}, nil
}
