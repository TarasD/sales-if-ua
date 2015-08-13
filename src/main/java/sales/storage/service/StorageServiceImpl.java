package sales.storage.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import sales.goods.domain.Good;
import sales.storage.domain.Storage;
import sales.storage.repository.StorageRepository;
import sales.users.domain.User;

import javax.transaction.Transactional;
import java.util.List;

/**
 * Created by volodya on 05.08.15.
 */
@Service
@Transactional
public class StorageServiceImpl implements StorageService{

    @Autowired
    StorageRepository repository;

    @Override
    public Storage get(long id) {
        return repository.findById(id);
    }

    @Override
    public List<Storage> getAll() {
        return repository.findAll();
    }

    @Override
    public Storage save(Storage storage) {
        return repository.save(storage);
    }

    @Override
    public void delete(long id) {
        repository.removeById(id);
    }

    @Override
    public List<Storage> getStoragesByGood(Good good) {
        return repository.findByGoodOrderByPriceAsc(good);
    }

    @Override
    public Storage getStorageByLeastPriceOfGood(Good good) {
        return repository.findByGoodOrderByPriceAsc(good).get(0);
    }

    @Override
    public List<Storage> getStoragesByUser(User user) {
        return repository.findByUser(user);
    }
}
