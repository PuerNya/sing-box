//go:build linux

package redirect

func (t *TProxy) initializeNFTables() error {
	// nft, err := nftables.New()
	// if err != nil {
	// 	return err
	// }
	// defer nft.CloseLasting()
	// _, err = nft.ListTablesOfFamily(nftables.TableFamilyIPv4)
	// if err != nil {
	// 	return err
	// }
	// t.useNFTables = true
	return nil
}

func (t *TProxy) cleanupNFTables() {
	// if t.networkListener != nil {
	// 	t.networkMonitor.UnregisterCallback(r.networkListener)
	// }
	// nft, err := nftables.New()
	// if err != nil {
	// 	return
	// }
	// nft.DelTable(&nftables.Table{
	// 	Name:   t.tableName,
	// 	Family: nftables.TableFamilyINet,
	// })
	// common.Must(t.configureOpenWRTFirewall4(nft, true))
	// _ = nft.Flush()
	// _ = nft.CloseLasting()
}
