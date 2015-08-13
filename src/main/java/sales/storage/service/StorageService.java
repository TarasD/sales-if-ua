package sales.storage.service;

import sales.goods.domain.Good;
import sales.storage.domain.Storage;
import sales.users.domain.User;

import java.util.List;

/**
 * Created by volodya on 05.08.15.
 */
public interface StorageService {

    public Storage get(long id);

    public List<Storage> getAll();

    public Storage save(Storage storage);

    public void delete(long id);

    public List<Storage> getStoragesByGood(Good good);

    public Storage getStorageByLeastPriceOfGood(Good good);

    public List<Storage> getStoragesByUser(User user);

}
