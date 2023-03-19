#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_transport_sas.h>
#include <scsi/scsi_dbg.h>
#include "mpt3sas_base.h"
static inline u8
_transport_get_port_id_by_sas_phy(struct sas_phy *phy)
{
	u8 port_id = 0xFF;
	struct hba_port *port = phy->hostdata;
	if (port)
		port_id = port->port_id;
	return port_id;
}
static struct _sas_node *
_transport_sas_node_find_by_sas_address(struct MPT3SAS_ADAPTER *ioc,
	u64 sas_address, struct hba_port *port)
{
			return &ioc->sas_hba;
			}
static enum sas_linkrate
_transport_convert_phy_link_rate(u8 link_rate)
{
	enum sas_linkrate rc;
	switch (link_rate) {
	case MPI2_SAS_NEG_LINK_RATE_1_5:
		rc = SAS_LINK_RATE_1_5_GBPS;
		break;
	case MPI2_SAS_NEG_LINK_RATE_3_0:
		rc = SAS_LINK_RATE_3_0_GBPS;
		break;
	case MPI2_SAS_NEG_LINK_RATE_6_0:
		rc = SAS_LINK_RATE_6_0_GBPS;
		break;
	case MPI25_SAS_NEG_LINK_RATE_12_0:
		rc = SAS_LINK_RATE_12_0_GBPS;
		break;
	case MPI2_SAS_NEG_LINK_RATE_PHY_DISABLED:
		rc = SAS_PHY_DISABLED;
		break;
	case MPI2_SAS_NEG_LINK_RATE_NEGOTIATION_FAILED:
		rc = SAS_LINK_RATE_FAILED;
		break;
	case MPI2_SAS_NEG_LINK_RATE_PORT_SELECTOR:
		rc = SAS_SATA_PORT_SELECTOR;
		break;
	case MPI2_SAS_NEG_LINK_RATE_SMP_RESET_IN_PROGRESS:
		rc = SAS_PHY_RESET_IN_PROGRESS;
		break;
	default:
	case MPI2_SAS_NEG_LINK_RATE_SATA_OOB_COMPLETE:
	case MPI2_SAS_NEG_LINK_RATE_UNKNOWN_LINK_RATE:
		rc = SAS_LINK_RATE_UNKNOWN;
		break;
	}
	return rc;
}
static int
_transport_set_identify(struct MPT3SAS_ADAPTER *ioc, u16 handle,
	struct sas_identify *identify)
{
	Mpi2SasDevicePage0_t sas_device_pg0;
	Mpi2ConfigReply_t mpi_reply;
	u32 device_info;
	u32 ioc_status;
	if (ioc->shost_recovery || ioc->pci_error_recovery) {
		ioc_info(ioc, "%s: host reset in progress!\n", __func__);
		return -EFAULT;
	}
	if ((mpt3sas_config_get_sas_device_pg0(ioc, &mpi_reply, &sas_device_pg0,
	    MPI2_SAS_DEVICE_PGAD_FORM_HANDLE, handle))) {
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return -ENXIO;
	}
	ioc_status = le16_to_cpu(mpi_reply.IOCStatus) &
	    MPI2_IOCSTATUS_MASK;
	if (ioc_status != MPI2_IOCSTATUS_SUCCESS) {
		ioc_err(ioc, "handle(0x%04x), ioc_status(0x%04x) failure at %s:%d/%s()!\n",
			handle, ioc_status, __FILE__, __LINE__, __func__);
		return -EIO;
	}
	memset(identify, 0, sizeof(struct sas_identify));
	device_info = le32_to_cpu(sas_device_pg0.DeviceInfo);
	identify->sas_address = le64_to_cpu(sas_device_pg0.SASAddress);
	identify->phy_identifier = sas_device_pg0.PhyNum;
	switch (device_info & MPI2_SAS_DEVICE_INFO_MASK_DEVICE_TYPE) {
	case MPI2_SAS_DEVICE_INFO_NO_DEVICE:
		identify->device_type = SAS_PHY_UNUSED;
		break;
	case MPI2_SAS_DEVICE_INFO_END_DEVICE:
		identify->device_type = SAS_END_DEVICE;
		break;
							}
	if (device_info & MPI2_SAS_DEVICE_INFO_SSP_INITIATOR)
		identify->initiator_port_protocols |= SAS_PROTOCOL_SSP;
	if (device_info & MPI2_SAS_DEVICE_INFO_STP_INITIATOR)
		identify->initiator_port_protocols |= SAS_PROTOCOL_STP;
	if (device_info & MPI2_SAS_DEVICE_INFO_SMP_INITIATOR)
		identify->initiator_port_protocols |= SAS_PROTOCOL_SMP;
	if (device_info & MPI2_SAS_DEVICE_INFO_SATA_HOST)
		identify->initiator_port_protocols |= SAS_PROTOCOL_SATA;
	if (device_info & MPI2_SAS_DEVICE_INFO_SSP_TARGET)
		identify->target_port_protocols |= SAS_PROTOCOL_SSP;
	if (device_info & MPI2_SAS_DEVICE_INFO_STP_TARGET)
		identify->target_port_protocols |= SAS_PROTOCOL_STP;
	if (device_info & MPI2_SAS_DEVICE_INFO_SMP_TARGET)
		identify->target_port_protocols |= SAS_PROTOCOL_SMP;
	if (device_info & MPI2_SAS_DEVICE_INFO_SATA_DEVICE)
		identify->target_port_protocols |= SAS_PROTOCOL_SATA;
	return 0;
}
static void
_transport_delete_port(struct MPT3SAS_ADAPTER *ioc,
	struct _sas_port *mpt3sas_port)
{
	u64 sas_address = mpt3sas_port->remote_identify.sas_address;
	struct hba_port *port = mpt3sas_port->hba_port;
	enum sas_device_type device_type =
	    mpt3sas_port->remote_identify.device_type;
		if (device_type == SAS_END_DEVICE)
		mpt3sas_device_remove_by_sas_address(ioc,
		    sas_address, port);
				}
static void
_transport_delete_phy(struct MPT3SAS_ADAPTER *ioc,
	struct _sas_port *mpt3sas_port, struct _sas_phy *mpt3sas_phy)
{
	list_del(&mpt3sas_phy->port_siblings);
	mpt3sas_port->num_phys--;
	sas_port_delete_phy(mpt3sas_port->port, mpt3sas_phy->phy);
	mpt3sas_phy->phy_belongs_to_port = 0;
}
static void
_transport_add_phy(struct MPT3SAS_ADAPTER *ioc, struct _sas_port *mpt3sas_port,
	struct _sas_phy *mpt3sas_phy)
{
	list_add_tail(&mpt3sas_phy->port_siblings, &mpt3sas_port->phy_list);
	mpt3sas_port->num_phys++;
	sas_port_add_phy(mpt3sas_port->port, mpt3sas_phy->phy);
	mpt3sas_phy->phy_belongs_to_port = 1;
}
void
mpt3sas_transport_add_phy_to_an_existing_port(struct MPT3SAS_ADAPTER *ioc,
	struct _sas_node *sas_node, struct _sas_phy *mpt3sas_phy,
	u64 sas_address, struct hba_port *port)
{
	struct _sas_port *mpt3sas_port;
	struct _sas_phy *phy_srch;
	if (mpt3sas_phy->phy_belongs_to_port == 1)
		return;
	if (!port)
		return;
	list_for_each_entry(mpt3sas_port, &sas_node->sas_port_list,
	    port_list) {
		if (mpt3sas_port->remote_identify.sas_address !=
		    sas_address)
			continue;
		if (mpt3sas_port->hba_port != port)
			continue;
		list_for_each_entry(phy_srch, &mpt3sas_port->phy_list,
		    port_siblings) {
			if (phy_srch == mpt3sas_phy)
				return;
		}
		_transport_add_phy(ioc, mpt3sas_port, mpt3sas_phy);
		return;
	}
}
void
mpt3sas_transport_del_phy_from_an_existing_port(struct MPT3SAS_ADAPTER *ioc,
	struct _sas_node *sas_node, struct _sas_phy *mpt3sas_phy)
{
	struct _sas_port *mpt3sas_port, *next;
	struct _sas_phy *phy_srch;
	if (mpt3sas_phy->phy_belongs_to_port == 0)
		return;
	list_for_each_entry_safe(mpt3sas_port, next, &sas_node->sas_port_list,
	    port_list) {
		list_for_each_entry(phy_srch, &mpt3sas_port->phy_list,
		    port_siblings) {
			if (phy_srch != mpt3sas_phy)
				continue;
			if (mpt3sas_port->num_phys == 1 && !ioc->shost_recovery)
				_transport_delete_port(ioc, mpt3sas_port);
			else
				_transport_delete_phy(ioc, mpt3sas_port,
				    mpt3sas_phy);
			return;
		}
	}
}
static void
_transport_sanity_check(struct MPT3SAS_ADAPTER *ioc, struct _sas_node *sas_node,
	u64 sas_address, struct hba_port *port)
{
	int i;
	for (i = 0; i < sas_node->num_phys; i++) {
		if (sas_node->phy[i].remote_identify.sas_address != sas_address)
			continue;
		if (sas_node->phy[i].port != port)
			continue;
		if (sas_node->phy[i].phy_belongs_to_port == 1)
			mpt3sas_transport_del_phy_from_an_existing_port(ioc,
			    sas_node, &sas_node->phy[i]);
	}
}
struct _sas_port *
mpt3sas_transport_port_add(struct MPT3SAS_ADAPTER *ioc, u16 handle,
	u64 sas_address, struct hba_port *hba_port)
{
	struct _sas_phy *mpt3sas_phy, *next;
	struct _sas_port *mpt3sas_port;
	unsigned long flags;
	struct _sas_node *sas_node;
	struct sas_rphy *rphy;
	struct _sas_device *sas_device = NULL;
	int i;
	struct sas_port *port;
	struct virtual_phy *vphy = NULL;
	if (!hba_port) {
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
		    __FILE__, __LINE__, __func__);
		return NULL;
	}
	mpt3sas_port = kzalloc(sizeof(struct _sas_port),
	    GFP_KERNEL);
	if (!mpt3sas_port) {
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return NULL;
	}
	INIT_LIST_HEAD(&mpt3sas_port->port_list);
	INIT_LIST_HEAD(&mpt3sas_port->phy_list);
	spin_lock_irqsave(&ioc->sas_node_lock, flags);
	sas_node = _transport_sas_node_find_by_sas_address(ioc,
	    sas_address, hba_port); 
	spin_unlock_irqrestore(&ioc->sas_node_lock, flags);
	if (!sas_node) {
		ioc_err(ioc, "%s: Could not find parent sas_address(0x%016llx)!\n",
			__func__, (u64)sas_address);
		goto out_fail;
	}
	if ((_transport_set_identify(ioc, handle,
	    &mpt3sas_port->remote_identify))) { 
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		goto out_fail;
	}
	if (mpt3sas_port->remote_identify.device_type == SAS_PHY_UNUSED) {
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		goto out_fail;
	}
	mpt3sas_port->hba_port = hba_port;
	_transport_sanity_check(ioc, sas_node,
	    mpt3sas_port->remote_identify.sas_address, hba_port);
	for (i = 0; i < sas_node->num_phys; i++) {
		if (sas_node->phy[i].remote_identify.sas_address !=
		    mpt3sas_port->remote_identify.sas_address)
			continue;
		if (sas_node->phy[i].port != hba_port)
			continue;
		list_add_tail(&sas_node->phy[i].port_siblings,
		    &mpt3sas_port->phy_list);
		mpt3sas_port->num_phys++;
		if (sas_node->handle <= ioc->sas_hba.num_phys) {
			if (!sas_node->phy[i].hba_vphy) {
				hba_port->phy_mask |= (1 << i);
				continue;
			}
			vphy = mpt3sas_get_vphy_by_phy(ioc, hba_port, i);
			if (!vphy) {
				ioc_err(ioc, "failure at %s:%d/%s()!\n",
				    __FILE__, __LINE__, __func__);
				goto out_fail;
			}
		}
	}
	if (!mpt3sas_port->num_phys) {
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		goto out_fail;
	}
	if (mpt3sas_port->remote_identify.device_type == SAS_END_DEVICE) {
		sas_device = mpt3sas_get_sdev_by_addr(ioc,
		    mpt3sas_port->remote_identify.sas_address,
		    mpt3sas_port->hba_port);
		if (!sas_device) {
			ioc_err(ioc, "failure at %s:%d/%s()!\n",
			    __FILE__, __LINE__, __func__);
			goto out_fail;
		}
		sas_device->pend_sas_rphy_add = 1;
	}
	if (!sas_node->parent_dev) {
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		goto out_fail;
	}
	port = sas_port_alloc_num(sas_node->parent_dev);
	if ((sas_port_add(port))) {
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		goto out_fail;
	}
	list_for_each_entry(mpt3sas_phy, &mpt3sas_port->phy_list,
	    port_siblings) {
														sas_port_add_phy(port, mpt3sas_phy->phy);
		mpt3sas_phy->phy_belongs_to_port = 1;
		mpt3sas_phy->port = hba_port;
	}
	mpt3sas_port->port = port;
	if (mpt3sas_port->remote_identify.device_type == SAS_END_DEVICE) {
		rphy = sas_end_device_alloc(port);
		sas_device->rphy = rphy;
		if (sas_node->handle <= ioc->sas_hba.num_phys) {
			if (!vphy)
				hba_port->sas_address =
				    sas_device->sas_address;
			else
				vphy->sas_address =
				    sas_device->sas_address;
		}
	} 
	rphy->identify = mpt3sas_port->remote_identify;
	if ((sas_rphy_add(rphy))) { 
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
	}
	if (mpt3sas_port->remote_identify.device_type == SAS_END_DEVICE) {
		sas_device->pend_sas_rphy_add = 0;
		sas_device_put(sas_device);
	}
	dev_info(&rphy->dev,
	    "add: handle(0x%04x), sas_addr(0x%016llx)\n", handle,
	    (unsigned long long)mpt3sas_port->remote_identify.sas_address);
	mpt3sas_port->rphy = rphy;
	spin_lock_irqsave(&ioc->sas_node_lock, flags);
	list_add_tail(&mpt3sas_port->port_list, &sas_node->sas_port_list);
	spin_unlock_irqrestore(&ioc->sas_node_lock, flags);
											return mpt3sas_port;
 out_fail:
	list_for_each_entry_safe(mpt3sas_phy, next, &mpt3sas_port->phy_list,
	    port_siblings)
		list_del(&mpt3sas_phy->port_siblings);
	kfree(mpt3sas_port);
	return NULL;
}
void
mpt3sas_transport_port_remove(struct MPT3SAS_ADAPTER *ioc, u64 sas_address,
	u64 sas_address_parent, struct hba_port *port)
{
	int i;
	unsigned long flags;
	struct _sas_port *mpt3sas_port, *next;
	struct _sas_node *sas_node;
	u8 found = 0;
	struct _sas_phy *mpt3sas_phy, *next_phy;
	struct hba_port *hba_port_next, *hba_port = NULL;
	struct virtual_phy *vphy, *vphy_next = NULL;
	if (!port)
		return;
	spin_lock_irqsave(&ioc->sas_node_lock, flags);
	sas_node = _transport_sas_node_find_by_sas_address(ioc,
	    sas_address_parent, port);
	if (!sas_node) {
		spin_unlock_irqrestore(&ioc->sas_node_lock, flags);
		return;
	}
	list_for_each_entry_safe(mpt3sas_port, next, &sas_node->sas_port_list,
	    port_list) {
		if (mpt3sas_port->remote_identify.sas_address != sas_address)
			continue;
		if (mpt3sas_port->hba_port != port)
			continue;
		found = 1;
		list_del(&mpt3sas_port->port_list);
		goto out;
	}
 out:
	if (!found) {
		spin_unlock_irqrestore(&ioc->sas_node_lock, flags);
		return;
	}
	if (sas_node->handle <= ioc->sas_hba.num_phys &&
	    (ioc->multipath_on_hba)) {
		if (port->vphys_mask) {
			list_for_each_entry_safe(vphy, vphy_next,
			    &port->vphys_list, list) {
				if (vphy->sas_address != sas_address)
					continue;
				ioc_info(ioc,
				    "remove vphy entry: %p of port:%p,from %d port's vphys list\n",
				    vphy, port, port->port_id);
				port->vphys_mask &= ~vphy->phy_mask;
				list_del(&vphy->list);
				kfree(vphy);
			}
		}
		list_for_each_entry_safe(hba_port, hba_port_next,
		    &ioc->port_table_list, list) {
			if (hba_port != port)
				continue;
			if ((hba_port->sas_address == sas_address ||
			    !hba_port->sas_address) && !hba_port->vphys_mask) {
				ioc_info(ioc,
				    "remove hba_port entry: %p port: %d from hba_port list\n",
				    hba_port, hba_port->port_id);
				list_del(&hba_port->list);
				kfree(hba_port);
			} else if (hba_port->sas_address == sas_address &&
			    hba_port->vphys_mask) {
				ioc_info(ioc,
				    "clearing sas_address from hba_port entry: %p port: %d from hba_port list\n",
				    hba_port, hba_port->port_id);
				port->sas_address = 0;
			}
			break;
		}
	}
	for (i = 0; i < sas_node->num_phys; i++) {
		if (sas_node->phy[i].remote_identify.sas_address == sas_address)
			memset(&sas_node->phy[i].remote_identify, 0 ,
			    sizeof(struct sas_identify));
	}
	spin_unlock_irqrestore(&ioc->sas_node_lock, flags);
	list_for_each_entry_safe(mpt3sas_phy, next_phy,
	    &mpt3sas_port->phy_list, port_siblings) {
														mpt3sas_phy->phy_belongs_to_port = 0;
		if (!ioc->remove_host)
			sas_port_delete_phy(mpt3sas_port->port,
						mpt3sas_phy->phy);
		list_del(&mpt3sas_phy->port_siblings);
	}
	if (!ioc->remove_host)
		sas_port_delete(mpt3sas_port->port);
	ioc_info(ioc, "%s: removed: sas_addr(0x%016llx)\n",
	    __func__, (unsigned long long)sas_address);
	kfree(mpt3sas_port);
}
int
mpt3sas_transport_add_host_phy(struct MPT3SAS_ADAPTER *ioc, struct _sas_phy
	*mpt3sas_phy, Mpi2SasPhyPage0_t phy_pg0, struct device *parent_dev)
{
	struct sas_phy *phy;
	int phy_index = mpt3sas_phy->phy_id;
	INIT_LIST_HEAD(&mpt3sas_phy->port_siblings);
	phy = sas_phy_alloc(parent_dev, phy_index);
	if (!phy) {
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		return -1;
	}
	if ((_transport_set_identify(ioc, mpt3sas_phy->handle,
	    &mpt3sas_phy->identify))) {
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		sas_phy_free(phy);
		return -1;
	}
	phy->identify = mpt3sas_phy->identify;
	mpt3sas_phy->attached_handle = le16_to_cpu(phy_pg0.AttachedDevHandle);
	if (mpt3sas_phy->attached_handle)
		_transport_set_identify(ioc, mpt3sas_phy->attached_handle,
		    &mpt3sas_phy->remote_identify);
	phy->identify.phy_identifier = mpt3sas_phy->phy_id;
	phy->negotiated_linkrate = _transport_convert_phy_link_rate(
	    phy_pg0.NegotiatedLinkRate & MPI2_SAS_NEG_LINK_RATE_MASK_PHYSICAL);
	phy->minimum_linkrate_hw = _transport_convert_phy_link_rate(
	    phy_pg0.HwLinkRate & MPI2_SAS_HWRATE_MIN_RATE_MASK);
	phy->maximum_linkrate_hw = _transport_convert_phy_link_rate(
	    phy_pg0.HwLinkRate >> 4);
	phy->minimum_linkrate = _transport_convert_phy_link_rate(
	    phy_pg0.ProgrammedLinkRate & MPI2_SAS_PRATE_MIN_RATE_MASK);
	phy->maximum_linkrate = _transport_convert_phy_link_rate(
	    phy_pg0.ProgrammedLinkRate >> 4);
	phy->hostdata = mpt3sas_phy->port;
	if ((sas_phy_add(phy))) {
		ioc_err(ioc, "failure at %s:%d/%s()!\n",
			__FILE__, __LINE__, __func__);
		sas_phy_free(phy);
		return -1;
	}
										mpt3sas_phy->phy = phy;
	return 0;
}
void
mpt3sas_transport_update_links(struct MPT3SAS_ADAPTER *ioc,
	u64 sas_address, u16 handle, u8 phy_number, u8 link_rate,
	struct hba_port *port)
{
	unsigned long flags;
	struct _sas_node *sas_node;
	struct _sas_phy *mpt3sas_phy;
	if (ioc->shost_recovery || ioc->pci_error_recovery)
		return;
	spin_lock_irqsave(&ioc->sas_node_lock, flags);
	sas_node = _transport_sas_node_find_by_sas_address(ioc,
	    sas_address, port);
	if (!sas_node) {
		spin_unlock_irqrestore(&ioc->sas_node_lock, flags);
		return;
	}
	mpt3sas_phy = &sas_node->phy[phy_number];
	mpt3sas_phy->attached_handle = handle;
	spin_unlock_irqrestore(&ioc->sas_node_lock, flags);
	if (handle && (link_rate >= MPI2_SAS_NEG_LINK_RATE_1_5)) {
		_transport_set_identify(ioc, handle,
		    &mpt3sas_phy->remote_identify);
																						mpt3sas_transport_add_phy_to_an_existing_port(ioc, sas_node,
		    mpt3sas_phy, mpt3sas_phy->remote_identify.sas_address,
		    port);
	} else
		memset(&mpt3sas_phy->remote_identify, 0 , sizeof(struct
		    sas_identify));
	if (mpt3sas_phy->phy)
		mpt3sas_phy->phy->negotiated_linkrate =
		    _transport_convert_phy_link_rate(link_rate);
								}
static inline void *
phy_to_ioc(struct sas_phy *phy)
{
	struct Scsi_Host *shost = dev_to_shost(phy->dev.parent);
	return shost_priv(shost);
}
static inline void *
rphy_to_ioc(struct sas_rphy *rphy)
{
	struct Scsi_Host *shost = dev_to_shost(rphy->dev.parent->parent);
	return shost_priv(shost);
}
struct sas_function_template mpt3sas_transport_functions = {
							};
struct scsi_transport_template *mpt3sas_transport_template;
