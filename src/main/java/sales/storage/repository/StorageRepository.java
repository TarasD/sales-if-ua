package sales.storage.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import sales.goods.domain.Good;
import sales.storage.domain.Storage;
import sales.users.domain.User;

import java.util.List;

/**
 * Created by volodya on 05.08.15.
 */
public interface StorageRepository extends JpaRepository<Storage, Long> {

    public Storage findById(long id);

    public void removeById(long id);

    public List<Storage> findByGoodOrderByPriceAsc(Good good);

    public List<Storage> findByUser(User user);

}
